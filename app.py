import os, secrets, hashlib, hmac, re, uuid
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
app=Flask(__name__,static_folder="public",static_url_path="/assets")
app.config["MAX_CONTENT_LENGTH"]=256*1024
def db():
    return psycopg.connect(os.environ["DATABASE_URL"],row_factory=dict_row,connect_timeout=10)
def data():
    if not request.is_json: abort(415)
    x=request.get_json()
    if not isinstance(x,dict): abort(400)
    return x
def digest(x): return hashlib.sha256(x.encode()).hexdigest()
def current():
    t=request.cookies.get("commerce_session","")
    if not t: return None
    with db() as c:
        return c.execute("SELECT a.id,a.email,a.name,a.role FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE token_hash=%s AND expires_at>now()", (digest(t),)).fetchone()
def protected(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args,**kwargs):
            a=current()
            if not a: abort(401)
            if role and a["role"]!=role: abort(403)
            return f(a,*args,**kwargs)
        return wrapped
    return decorator
@app.before_request
def origin_guard():
    if request.method not in ("GET","HEAD","OPTIONS"):
        if not request.is_json: abort(415)
        origin=request.headers.get("Origin")
        if origin and origin.rstrip("/") not in {request.host_url.rstrip("/"),"https://"+request.host}:
            abort(403)
@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"]="nosniff"
    r.headers["X-Frame-Options"]="DENY"
    r.headers["Referrer-Policy"]="strict-origin-when-cross-origin"
    r.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.path.startswith("/api/"): r.headers["Cache-Control"]="no-store"
    return r
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(409)
@app.errorhandler(415)
@app.errorhandler(429)
def errors(e): return jsonify(error={400:"Dados inválidos",401:"Entre na sua conta",403:"Acesso não autorizado",404:"Não encontrado",409:"Conflito ou estoque insuficiente",415:"Formato inválido",429:"Tente novamente mais tarde"}.get(e.code,"Erro")),e.code
@app.get("/health")
def health():
    with db() as c: c.execute("SELECT 1")
    return {"ok":True}
@app.get("/")
@app.get("/produto/<slug>")
@app.get("/admin")
@app.get("/conta")
@app.get("/carrinho")
def page(slug=None): return send_from_directory("public","index.html")
def catalog(admin=False):
    with db() as c:
        products=c.execute("SELECT * FROM products "+("" if admin else "WHERE active")+" ORDER BY created_at DESC").fetchall()
        variants=c.execute("SELECT * FROM product_variants "+("" if admin else "WHERE active")+" ORDER BY storage_gb NULLS FIRST,created_at").fetchall()
        images=c.execute("SELECT variant_id,url,alt_text,position FROM product_images ORDER BY position").fetchall()
    for v in variants: v["images"]=[i for i in images if i["variant_id"]==v["id"]]
    for p in products: p["variants"]=[v for v in variants if v["product_id"]==p["id"]]
    return products
@app.get("/api/products")
def products(): return jsonify(catalog())
@app.get("/api/me")
def me(): return jsonify(current())
def login_response(a):
    t=secrets.token_urlsafe(32)
    with db() as c: c.execute("INSERT INTO sessions(token_hash,account_id,expires_at) VALUES(%s,%s,now()+interval '7 days')",(digest(t),a["id"]))
    r=make_response(jsonify({k:a[k] for k in ("id","name","email","role")}))
    r.set_cookie("commerce_session",t,httponly=True,secure=os.getenv("COOKIE_SECURE","true")=="true",samesite="Lax",max_age=604800,path="/")
    return r
def credentials(x):
    email=str(x.get("email","")).strip().lower(); pw=x.get("password",""); name=str(x.get("name","")).strip()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email) or len(email)>254 or not isinstance(pw,str) or not 12<=len(pw)<=128 or not 1<=len(name)<=100: abort(400)
    return email,pw,name
@app.post("/api/register")
def register():
    email,pw,name=credentials(data())
    with db() as c:
        a=c.execute("INSERT INTO accounts(email,password_hash,name) VALUES(%s,%s,%s) ON CONFLICT DO NOTHING RETURNING id,email,name,role",(email,generate_password_hash(pw),name)).fetchone()
    if not a: abort(409)
    return login_response(a)
@app.post("/api/admin/setup")
def setup():
    x=data(); token=os.getenv("ADMIN_SETUP_TOKEN","")
    if not token or len(token)<32 or not hmac.compare_digest(str(x.get("token","")),token): abort(403)
    email,pw,name=credentials(x)
    with db() as c:
        c.execute("SELECT pg_advisory_xact_lock(880018)")
        if c.execute("SELECT 1 FROM accounts WHERE role='admin'").fetchone(): abort(409)
        a=c.execute("INSERT INTO accounts(email,password_hash,name,role) VALUES(%s,%s,%s,'admin') ON CONFLICT DO NOTHING RETURNING id,email,name,role",(email,generate_password_hash(pw),name)).fetchone()
        if not a: abort(409)
    return login_response(a)
@app.post("/api/login")
def login():
    x=data(); email=str(x.get("email","")).lower().strip(); pw=x.get("password","")
    if not isinstance(pw,str) or len(pw)>128: abort(400)
    with db() as c:
        key=digest(email+"|"+str(request.remote_addr))
        c.execute("DELETE FROM login_attempts WHERE created_at<now()-interval '15 minutes'")
        c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",(key,))
        if c.execute("SELECT count(*) AS n FROM login_attempts WHERE key=%s",(key,)).fetchone()["n"]>=8: abort(429)
        a=c.execute("SELECT * FROM accounts WHERE email=%s",(email,)).fetchone()
        ok=bool(a and check_password_hash(a["password_hash"],pw))
        if not ok: c.execute("INSERT INTO login_attempts(key) VALUES(%s)",(key,))
    if not ok: abort(401)
    return login_response(a)
@app.post("/api/logout")
def logout():
    data()
    with db() as c: c.execute("DELETE FROM sessions WHERE token_hash=%s",(digest(request.cookies.get("commerce_session","")),))
    r=make_response(jsonify(ok=True)); r.delete_cookie("commerce_session",path="/"); return r
@app.get("/api/admin/products")
@protected("admin")
def admin_products(a): return jsonify(catalog(True))
@app.post("/api/admin/products")
@protected("admin")
def save_product(a):
    x=data(); name=str(x.get("name","")).strip(); slug=str(x.get("slug","")).strip(); category=x.get("category")
    if not name or len(name)>150 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*",slug) or category not in ("iPhone","iPad","Mac","Watch","AirPods","Acessórios"): abort(400)
    vs=x.get("variants",[])
    if not isinstance(vs,list) or len(vs)>200 or not vs: abort(400)
    seen=set()
    for v in vs:
        if not isinstance(v,dict) or not v.get("sku") or v["sku"] in seen or not v.get("color_name"): abort(400)
        seen.add(v["sku"])
        if any(not re.fullmatch(r"#[0-9a-fA-F]{6}",str(v.get(k,""))) for k in ("color_hex","theme_hex")): abort(400)
        if any(type(v.get(k)) is not int or not 0<=v[k]<=100000000 for k in ("price_cents","stock")): abort(400)
        if v.get("storage_gb") is not None and (type(v["storage_gb"]) is not int or v["storage_gb"]<=0): abort(400)
        if v.get("condition","new") not in ("new","used","refurbished"): abort(400)
        if not isinstance(v.get("images",[]),list) or len(v.get("images",[]))>20: abort(400)
        if any(not isinstance(i,str) or not i.startswith("https://") or len(i)>2000 for i in v.get("images",[])): abort(400)
    try:
        with db() as c:
            p=c.execute("INSERT INTO products(slug,name,category,description,specs,active) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(slug) DO UPDATE SET name=excluded.name,category=excluded.category,description=excluded.description,specs=excluded.specs,active=excluded.active,updated_at=now() RETURNING id",(slug,name,category,str(x.get("description","")),Jsonb(x.get("specs",{})),x.get("active") is True)).fetchone()["id"]
            c.execute("UPDATE product_variants SET active=false WHERE product_id=%s",(p,))
            for v in vs:
                row=c.execute("INSERT INTO product_variants(product_id,sku,color_name,color_hex,theme_hex,storage_gb,condition,price_cents,stock,active) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(sku) DO UPDATE SET color_name=excluded.color_name,color_hex=excluded.color_hex,theme_hex=excluded.theme_hex,storage_gb=excluded.storage_gb,condition=excluded.condition,price_cents=excluded.price_cents,stock=excluded.stock,active=excluded.active WHERE product_variants.product_id=excluded.product_id RETURNING id",(p,v["sku"],v["color_name"],v["color_hex"],v["theme_hex"],v.get("storage_gb"),v.get("condition","new"),v["price_cents"],v["stock"],v.get("active",True) is True)).fetchone()
                if not row: abort(409)
                c.execute("DELETE FROM product_images WHERE variant_id=%s",(row["id"],))
                for pos,url in enumerate(v.get("images",[])): c.execute("INSERT INTO product_images(variant_id,url,alt_text,position) VALUES(%s,%s,%s,%s)",(row["id"],url,name,pos))
    except psycopg.IntegrityError: abort(409)
    return {"id":p}
@app.get("/api/orders")
@protected()
def my_orders(a):
    with db() as c: return jsonify(c.execute("SELECT id,status,total_cents,created_at FROM orders WHERE account_id=%s ORDER BY created_at DESC",(a["id"],)).fetchall())
@app.get("/api/admin/orders")
@protected("admin")
def admin_orders(a):
    with db() as c: return jsonify(c.execute("SELECT o.id,o.status,o.total_cents,o.created_at,a.email FROM orders o LEFT JOIN accounts a ON a.id=o.account_id ORDER BY o.created_at DESC LIMIT 200").fetchall())
@app.get("/api/admin/customers")
@protected("admin")
def customers(a):
    with db() as c: return jsonify(c.execute("SELECT id,name,email,created_at FROM accounts WHERE role='customer' ORDER BY created_at DESC LIMIT 200").fetchall())
@app.post("/api/orders")
@protected()
def order(a):
    x=data()
    items=x.get("items")
    address=x.get("address")
    if not isinstance(items,list) or not 1<=len(items)<=30 or not isinstance(address,dict): abort(400)
    address={k:str(address.get(k,"")).strip() for k in ("name","phone","cep","street","number","complement","district","city","state")}
    if not all(address[k] for k in ("name","phone","cep","street","number","district","city","state")) or any(len(v)>180 for v in address.values()): abort(400)
    if not re.fullmatch(r"[0-9]{5}-?[0-9]{3}",address["cep"]) or not re.fullmatch(r"[A-Za-z]{2}",address["state"]): abort(400)
    quantities={}
    for item in items:
        if not isinstance(item,dict) or type(item.get("qty")) is not int or not 1<=item["qty"]<=10: abort(400)
        try: vid=str(uuid.UUID(str(item.get("id"))))
        except (ValueError,TypeError): abort(400)
        quantities[vid]=quantities.get(vid,0)+item["qty"]
        if quantities[vid]>10: abort(400)
    with db() as c:
        c.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",(str(a["id"]),))
        if c.execute("SELECT count(*) AS n FROM orders WHERE account_id=%s AND created_at>now()-interval '1 hour'",(a["id"],)).fetchone()["n"]>=5: abort(429)
        lines=[]; total=0
        for vid,q in sorted(quantities.items()):
            v=c.execute("SELECT v.id,v.sku,v.price_cents,v.stock,p.name FROM product_variants v JOIN products p ON p.id=v.product_id WHERE v.id=%s AND v.active AND p.active",(vid,)).fetchone()
            if not v or v["stock"]<q: abort(409)
            total+=q*v["price_cents"]; lines.append((v,q))
        # Requests do not reserve inventory or authorize payment; confirmation is manual.
        o=c.execute("INSERT INTO orders(account_id,subtotal_cents,shipping_address) VALUES(%s,%s,%s) RETURNING id,status,total_cents",(a["id"],total,Jsonb(address))).fetchone()
        for v,q in lines: c.execute("INSERT INTO order_items(order_id,variant_id,product_name,sku,quantity,unit_price_cents) VALUES(%s,%s,%s,%s,%s,%s)",(o["id"],v["id"],v["name"],v["sku"],q,v["price_cents"]))
    return jsonify(o),201
@app.get("/api/admin/orders/<oid>")
@protected("admin")
def admin_order_detail(a,oid):
    try: oid=uuid.UUID(oid)
    except ValueError: abort(404)
    with db() as c:
        o=c.execute("SELECT id,status,subtotal_cents,shipping_address,created_at FROM orders WHERE id=%s",(oid,)).fetchone()
        if not o: abort(404)
        o["items"]=c.execute("SELECT product_name,sku,quantity,unit_price_cents FROM order_items WHERE order_id=%s",(oid,)).fetchall()
    return jsonify(o)
@app.post("/api/admin/orders/<oid>/status")
@protected("admin")
def order_status(a,oid):
    try: oid=uuid.UUID(oid)
    except ValueError: abort(404)
    status=data().get("status")
    # Do not mark any order paid without a verified payment integration.
    if status!="cancelled": abort(400)
    with db() as c:
        o=c.execute("UPDATE orders SET status='cancelled' WHERE id=%s AND status='pending' RETURNING id",(oid,)).fetchone()
        if not o: abort(409)
    return {"ok":True}
