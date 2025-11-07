from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime, timedelta
from pymongo import MongoClient
from bson import ObjectId
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS  # Importa CORS per gestire le richieste cross-origin (se necessario)
import bcrypt  # Per fallback se werkzeug non funziona

# ===== CONFIGURAZIONE =====
MONGO_URI = "mongodb+srv://bet365odds:Aurora86@cluster0.svytet0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)

app = Flask(__name__)
app.secret_key = "supersecretgestionale"
app.permanent_session_lifetime = timedelta(minutes=20)  # Timeout della sessione

# Abilitare CORS (se necessario)
CORS(app)

# ===== LOGIN =====
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

users_col = client["gestionale"]["utenti"]
movimenti_col = client["gestionale"]["movimenti"]

class User(UserMixin):
    def __init__(self, user):
        self.id = str(user["_id"])
        self.username = user["username"]
        # Salva anche l'ID originale per compatibilità con movimenti vecchi
        self.original_id = user.get("id") if "id" in user else None

@login_manager.user_loader
def load_user(user_id):
    user = users_col.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user)
    return None

# ===== ROTTE =====

@app.route("/")
def home():
    return render_template("index.html", nome="Mario")

@app.route("/ciao/<nome>")
def saluta(nome):
    return f"Ciao, {nome}!"

@app.route("/quote")
def quote():
    db = client["bet365"]
    col = db["calcio"]
    eventi = list(col.find().sort("start_time_date", 1).limit(100))

    for ev in eventi:
        if "start_time_date" in ev:
            ev["start_time_date"] = ev["start_time_date"] + timedelta(hours=1)
            ev["start_time"] = ev["start_time_date"].strftime("%Y-%m-%d %H:%M:%S")

    return render_template("quote.html", eventi=eventi)

# ===== GESTIONE PRODOTTI =====
@app.route("/prodotti")
def prodotti():
    col = client["libreria"]["prodotti"]
    prodotti = list(col.find())
    return render_template("prodotti.html", prodotti=prodotti)

@app.route("/prodotti/aggiungi", methods=["POST"])
def aggiungi_prodotto():
    col = client["libreria"]["prodotti"]
    nome = request.form["nome"]
    marca = request.form["marca"]
    quantita = int(request.form["quantita"])
    col.insert_one({"nome": nome, "marca": marca, "quantita": quantita})
    flash("✅ Prodotto aggiunto!", "success")
    return redirect(url_for("prodotti"))

@app.route("/prodotti/elimina/<id>", methods=["POST"])
def elimina_prodotto(id):
    col = client["libreria"]["prodotti"]
    col.delete_one({"_id": ObjectId(id)})
    flash("❌ Prodotto eliminato!", "danger")
    return redirect(url_for("prodotti"))

@app.route("/prodotti/modifica/<id>")
def modifica_prodotto(id):
    col = client["libreria"]["prodotti"]
    prodotto = col.find_one({"_id": ObjectId(id)})
    return render_template("modifica_prodotto.html", prodotto=prodotto)

@app.route("/prodotti/modifica/<id>", methods=["POST"])
def salva_modifica_prodotto(id):
    col = client["libreria"]["prodotti"]
    nome = request.form["nome"]
    marca = request.form["marca"]
    quantita = int(request.form["quantita"])
    col.update_one({"_id": ObjectId(id)}, {"$set": {"nome": nome, "marca": marca, "quantita": quantita}})
    flash("✏️ Prodotto modificato!", "info")
    return redirect(url_for("prodotti"))
@app.route("/libri")
def libri():
    col = client["libreria"]["libri"]
    libri = list(col.find())
    return render_template("libri.html", libri=libri)

# ===== GESTIONE MOVIMENTI =====
@app.route("/gestionale", methods=["GET", "POST"])
@login_required
def gestionale():
    user_id = current_user.id

    # Inserimento o modifica movimento
    if request.method == "POST":
        azione = request.form.get("azione")
        tipo = request.form.get("tipo")
        descrizione = request.form.get("descrizione")
        importo = float(request.form.get("importo", 0))

        if azione == "inserisci":
            movimenti_col.insert_one({
                "user_id": user_id,
                "tipo": tipo,
                "descrizione": descrizione,
                "importo": importo,
                "data": datetime.now()
            })
            flash("✅ Movimento inserito con successo", "success")
            return redirect(url_for("gestionale"))
        elif azione == "modifica":
            mov_id = request.form.get("id")
            print(f"DEBUG: Modifica movimento - ID: {mov_id}, user_id: {user_id} (tipo: {type(user_id)})")
            
            # Prima verifica se il movimento esiste
            try:
                movimento_esistente = movimenti_col.find_one({"_id": ObjectId(mov_id)})
                if movimento_esistente:
                    print(f"DEBUG: Movimento trovato - user_id nel DB: {movimento_esistente.get('user_id')} (tipo: {type(movimento_esistente.get('user_id'))})")
                else:
                    print(f"DEBUG: Movimento con ID {mov_id} non trovato nel database")
            except Exception as e:
                print(f"DEBUG: Errore durante ricerca movimento: {e}")
            
            # Prova a modificare con user_id come stringa
            result = movimenti_col.update_one(
                {"_id": ObjectId(mov_id), "user_id": user_id},
                {"$set": {"tipo": tipo, "descrizione": descrizione, "importo": importo}}
            )
            print(f"DEBUG: Tentativo 1 - user_id stringa: {result.matched_count} documenti modificati")
            
            # Se non trova nulla, prova anche con user_id come numero
            if result.matched_count == 0:
                try:
                    user_id_int = int(user_id) if user_id.isdigit() else None
                    if user_id_int is not None:
                        result = movimenti_col.update_one(
                            {"_id": ObjectId(mov_id), "user_id": user_id_int},
                            {"$set": {"tipo": tipo, "descrizione": descrizione, "importo": importo}}
                        )
                        print(f"DEBUG: Tentativo 2 - user_id numerico ({user_id_int}): {result.matched_count} documenti modificati")
                except (ValueError, AttributeError) as e:
                    print(f"DEBUG: Errore conversione user_id: {e}")
            
            # Se ancora non trova nulla, prova senza filtro user_id (solo per debug)
            if result.matched_count == 0:
                try:
                    result_no_user = movimenti_col.update_one(
                        {"_id": ObjectId(mov_id)},
                        {"$set": {"tipo": tipo, "descrizione": descrizione, "importo": importo}}
                    )
                    print(f"DEBUG: Tentativo 3 - senza filtro user_id: {result_no_user.matched_count} documenti modificati")
                    if result_no_user.matched_count > 0:
                        result = result_no_user
                except Exception as e:
                    print(f"DEBUG: Errore tentativo senza user_id: {e}")
            
            if result.matched_count > 0:
                flash("✏️ Movimento modificato con successo", "info")
            else:
                flash("❌ Errore: movimento non trovato o non autorizzato", "danger")
                print(f"DEBUG: Nessun documento modificato. ID: {mov_id}, user_id: {user_id}")
            
            return redirect(url_for("gestionale"))

    # Eliminazione movimento
    elimina_id = request.args.get("elimina")
    if elimina_id:
        movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id})
        flash("❌ Movimento eliminato!", "danger")
        return redirect(url_for("gestionale"))

    # Lista movimenti e saldo
    # Debug: verifica user_id
    print(f"DEBUG: Caricamento movimenti per user_id: {user_id} (tipo: {type(user_id)})")
    
    # Prova a cercare i movimenti
    try:
        # Cerca con user_id come stringa (formato nuovo)
        movimenti_cursor = movimenti_col.find({"user_id": user_id})
        movimenti = list(movimenti_cursor)
        
        # Se non trova nulla, prova anche con user_id come numero (formato vecchio)
        if len(movimenti) == 0:
            try:
                # Prova a convertire user_id in numero
                user_id_int = int(user_id) if user_id.isdigit() else None
                if user_id_int is not None:
                    movimenti_cursor = movimenti_col.find({"user_id": user_id_int})
                    movimenti = list(movimenti_cursor)
                    print(f"DEBUG: Trovati {len(movimenti)} movimenti con user_id come numero ({user_id_int})")
            except (ValueError, AttributeError):
                pass
        
        # Se ancora non trova nulla, prova con l'ID numerico dell'utente (se presente)
        if len(movimenti) == 0 and hasattr(current_user, 'original_id') and current_user.original_id is not None:
            try:
                movimenti_cursor = movimenti_col.find({"user_id": current_user.original_id})
                movimenti = list(movimenti_cursor)
                print(f"DEBUG: Trovati {len(movimenti)} movimenti con original_id ({current_user.original_id})")
            except:
                pass
        
        # Se ancora non trova nulla, prova anche con ObjectId (per compatibilità con dati vecchi)
        if len(movimenti) == 0:
            try:
                movimenti_cursor = movimenti_col.find({"user_id": ObjectId(user_id)})
                movimenti = list(movimenti_cursor)
                print(f"DEBUG: Trovati {len(movimenti)} movimenti con ObjectId")
            except:
                pass
        
        # Se ancora non trova nulla, usa una query $or per cercare tutti i formati possibili
        if len(movimenti) == 0:
            try:
                from pymongo import MongoClient
                query = {
                    "$or": [
                        {"user_id": user_id},
                        {"user_id": int(user_id)} if user_id.isdigit() else None,
                        {"user_id": ObjectId(user_id)}
                    ]
                }
                # Rimuovi None dalla query
                query["$or"] = [q for q in query["$or"] if q is not None]
                movimenti_cursor = movimenti_col.find(query)
                movimenti = list(movimenti_cursor)
                print(f"DEBUG: Trovati {len(movimenti)} movimenti con query $or")
            except Exception as e:
                print(f"DEBUG: Errore con query $or: {e}")
        
        # Ordina manualmente per data (se presente) o per _id
        if movimenti:
            movimenti.sort(key=lambda x: x.get("data") if x.get("data") else x.get("_id"), reverse=True)
        
        print(f"DEBUG: Trovati {len(movimenti)} movimenti totali")
        if len(movimenti) > 0:
            print(f"DEBUG: Primo movimento: tipo={movimenti[0].get('tipo')}, descrizione={movimenti[0].get('descrizione')}, user_id nel DB={movimenti[0].get('user_id')} (tipo: {type(movimenti[0].get('user_id'))})")
    except Exception as e:
        print(f"ERRORE durante caricamento movimenti: {e}")
        import traceback
        traceback.print_exc()
        movimenti = []
    
    # Calcola totali (gestisce anche il caso di movimenti vuoti)
    entrate = sum(m.get("importo", 0) for m in movimenti if m.get("tipo") == "entrata")
    uscite = sum(m.get("importo", 0) for m in movimenti if m.get("tipo") == "uscita")
    saldo = entrate - uscite

    return render_template("gestionale.html", movimenti=movimenti,
                           entrate=entrate, uscite=uscite, saldo=saldo, username=current_user.username)

# ===== LOGIN / LOGOUT =====
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Ricevi i dati come JSON
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        # Cerca l'utente nel database
        user = users_col.find_one({"username": username})
        
        if user:
            # Controlla se la password memorizzata è bytes o stringa
            stored_password = user["password"]
            print(f"DEBUG: Tipo password: {type(stored_password)}, lunghezza: {len(stored_password) if stored_password else 0}")
            print(f"DEBUG: Valore completo: {repr(stored_password)}")
            print(f"DEBUG: Primi 50 caratteri: {repr(stored_password[:50]) if stored_password else 'VUOTA'}")
            
            # Se è bytes, convertila in stringa (check_password_hash richiede una stringa)
            if isinstance(stored_password, bytes):
                print(f"DEBUG: Password è bytes, lunghezza: {len(stored_password)}, primi 20 bytes: {stored_password[:20]}")
                try:
                    # Prova prima con UTF-8
                    stored_password = stored_password.decode('utf-8')
                    print(f"DEBUG: Decodifica UTF-8 riuscita: {stored_password[:30]}...")
                except UnicodeDecodeError as e:
                    print(f"DEBUG: Errore UTF-8: {e}")
                    try:
                        # Se UTF-8 fallisce, prova con latin-1 (più permissivo)
                        stored_password = stored_password.decode('latin-1')
                        print(f"DEBUG: Decodifica latin-1 riuscita: {stored_password[:30]}...")
                    except Exception as e2:
                        print(f"Errore: impossibile decodificare la password: {e2}")
                        return jsonify({"success": False, "message": "Errore nel formato della password memorizzata"}), 500
                
                # Se la decodifica è riuscita, aggiorna il database con la stringa invece dei bytes
                # Questo corregge il problema per le prossime volte
                users_col.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"password": stored_password}}
                )
                print(f"DEBUG: Password corretta nel database (convertita da bytes a stringa)")
            
            # Verifica che la password memorizzata sia valida (deve essere una stringa non vuota che inizia con $)
            if not stored_password:
                print(f"ERRORE: Password memorizzata è vuota!")
                return jsonify({"success": False, "message": "Password memorizzata non valida"}), 500
            
            if not isinstance(stored_password, str):
                print(f"ERRORE: Password memorizzata non è una stringa: {type(stored_password)}")
                return jsonify({"success": False, "message": "Password memorizzata non valida"}), 500
            
            # Salva il valore originale per il confronto
            original_password = stored_password
            
            # Pulisci la password da eventuali caratteri nascosti o whitespace
            # Werkzeug supporta diversi formati: bcrypt ($2a$, $2b$, $2y$), scrypt, pbkdf2, ecc.
            stored_password = stored_password.strip()
            # Rimuovi caratteri di controllo invisibili ma mantieni tutti i caratteri stampabili
            # (werkzeug gestisce diversi formati, quindi non filtriamo troppo)
            stored_password = ''.join(char for char in stored_password if char.isprintable() or char in ['\n', '\r', '\t'])
            stored_password = stored_password.strip()
            
            # Verifica che la lunghezza sia ragionevole (almeno 20 caratteri per qualsiasi hash)
            if len(stored_password) < 20:
                print(f"ERRORE: Password memorizzata troppo corta ({len(stored_password)} caratteri): {repr(stored_password)}")
                return jsonify({"success": False, "message": "Password memorizzata non valida (troncata?)"}), 500
            
            # Se la password è stata pulita, aggiorna il database
            if stored_password != original_password:
                users_col.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"password": stored_password}}
                )
                print(f"DEBUG: Password pulita e aggiornata nel database (rimossi caratteri nascosti)")
            
            # Verifica rapida del formato (solo per debug)
            # Werkzeug supporta: bcrypt ($2a$, $2b$, $2y$), scrypt, pbkdf2, ecc.
            if stored_password.startswith('$'):
                print(f"DEBUG: Hash sembra essere bcrypt (inizia con $)")
            elif stored_password.startswith('scrypt'):
                print(f"DEBUG: Hash sembra essere scrypt")
            elif stored_password.startswith('pbkdf2'):
                print(f"DEBUG: Hash sembra essere pbkdf2")
            else:
                print(f"DEBUG: Hash formato sconosciuto, ma provo comunque la verifica...")
            
            print(f"DEBUG: Password valida (lunghezza: {len(stored_password)}), verifico hash...")
            # Verifica che la password memorizzata sia valida
            # check_password_hash richiede: (hash_stringa, password_stringa)
            password_valid = False
            try:
                password_valid = check_password_hash(stored_password, password)
            except ValueError as e:
                print(f"ERRORE durante verifica hash con werkzeug: {e}")
                # Fallback: prova con bcrypt direttamente solo se l'hash sembra essere bcrypt
                if stored_password.startswith('$2'):
                    print(f"Tento con bcrypt direttamente (hash sembra essere bcrypt)...")
                    try:
                        # Se l'hash è una stringa, convertila in bytes per bcrypt
                        if isinstance(stored_password, str):
                            stored_password_bytes = stored_password.encode('utf-8')
                        else:
                            stored_password_bytes = stored_password
                        
                        # Verifica con bcrypt
                        password_valid = bcrypt.checkpw(password.encode('utf-8'), stored_password_bytes)
                        print(f"Verifica bcrypt: {password_valid}")
                        
                        # Se funziona, rigenera la password con werkzeug per compatibilità futura
                        if password_valid:
                            new_hash = generate_password_hash(password)
                            users_col.update_one(
                                {"_id": user["_id"]},
                                {"$set": {"password": new_hash}}
                            )
                            print(f"Password rigenerata con werkzeug per compatibilità futura")
                    except Exception as bcrypt_error:
                        print(f"ERRORE anche con bcrypt: {bcrypt_error}")
                        return jsonify({"success": False, "message": f"Errore nel formato della password: {str(e)}. La password nel database potrebbe essere corrotta."}), 500
                else:
                    # Se non è bcrypt, non possiamo usare bcrypt come fallback
                    print(f"Hash non è bcrypt, non posso usare bcrypt come fallback")
                    return jsonify({"success": False, "message": f"Errore nel formato della password: {str(e)}. La password nel database potrebbe essere corrotta."}), 500
            
            if password_valid:
                login_user(User(user))  # Logga l'utente, assicurati che la tua User sia configurata correttamente
                return jsonify({"success": True, "message": "Login riuscito"})
            else:
                return jsonify({"success": False, "message": "Credenziali errate ❌"}), 401
        else:
            return jsonify({"success": False, "message": "Utente non trovato ❌"}), 404

    return render_template("login.html")

@app.route("/bet365")
def bet365():
    return render_template("bet365.html")

@app.route("/api/events")
def api_events():
    """API endpoint per ottenere gli eventi sportivi da MongoDB"""
    sport = request.args.get("sport", "calcio")
    limit = int(request.args.get("limit", 100))
    
    try:
        db = client["bet365"]
        col = db[sport]
        
        # Recupera eventi ordinati per data
        eventi = list(col.find().sort("start_time_date", 1).limit(limit))
        
        # Aggiungi 1 ora all'orario di ogni evento (orario MongoDB + 1 ora per bet365)
        for ev in eventi:
            if "start_time_date" in ev:
                ev["start_time_date"] = ev["start_time_date"] + timedelta(hours=1)
                ev["start_time"] = ev["start_time_date"].strftime("%Y-%m-%d %H:%M:%S")
            # Converti ObjectId in stringa per JSON
            if "_id" in ev:
                ev["_id"] = str(ev["_id"])
        
        return jsonify({
            "success": True,
            "results": eventi,
            "count": len(eventi)
        })
    except Exception as e:
        print(f"ERRORE API events: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "results": []
        }), 500

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("✅ Disconnessione avvenuta con successo.", "success")
    return redirect(url_for("login"))

# ===== CREAZIONE UTENTE DI TEST =====
if __name__ == "__main__":
    if users_col.count_documents({"username": "admin"}) == 0:
        users_col.insert_one({
            "username": "admin",
            "password": generate_password_hash("password123")
        })
    app.run(debug=True)
