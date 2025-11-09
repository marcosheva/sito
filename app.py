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
CORS(app, resources={r"/*": {"origins": "*"}})

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
@login_required
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
    nome = request.form.get("nome", "")
    marca = request.form.get("marca", "")
    quantita = int(request.form.get("quantita", 0) or 0)
    col.update_one({"_id": ObjectId(id)}, {"$set": {"nome": nome, "marca": marca, "quantita": quantita}})
    flash("✏️ Prodotto modificato!", "info")
    return redirect(url_for("prodotti"))
@app.route("/libri")
def libri():
    col = client["libreria"]["libri"]
    libri = list(col.find())
    return render_template("libri.html", libri=libri)

@app.route("/libri/aggiungi", methods=["POST"])
def aggiungi_libro():
    col = client["libreria"]["libri"]
    titolo = request.form.get("titolo", "")
    autore = request.form.get("autore", "")
    anno = int(request.form.get("anno", 0))
    genere = request.form.get("genere", "")
    isbn = int(request.form.get("isbn", 0))
    quantita = int(request.form.get("quantita", 0))
    col.insert_one({
        "titolo": titolo,
        "autore": autore,
        "anno": anno,
        "genere": genere,
        "isbn": isbn,
        "quantita": quantita
    })
    flash("✅ Libro aggiunto!", "success")
    return redirect(url_for("libri"))

@app.route("/libri/elimina/<id>", methods=["POST"])
def elimina_libro(id):
    col = client["libreria"]["libri"]
    col.delete_one({"_id": ObjectId(id)})
    flash("❌ Libro eliminato!", "danger")
    return redirect(url_for("libri"))

@app.route("/libri/modifica/<id>")
def modifica_libro(id):
    col = client["libreria"]["libri"]
    libro = col.find_one({"_id": ObjectId(id)})
    return render_template("modifica_libro.html", libro=libro)

@app.route("/libri/modifica/<id>", methods=["POST"])
def salva_modifica_libro(id):
    col = client["libreria"]["libri"]
    titolo = request.form.get("titolo", "")
    autore = request.form.get("autore", "")
    genere = request.form.get("genere", "")
    quantita = int(request.form.get("quantita", 0) or 0)
    anno = int(request.form.get("anno", 0) or 0)
    isbn = int(request.form.get("isbn", 0) or 0)
    col.update_one({"_id": ObjectId(id)}, {"$set": {"titolo": titolo, "autore": autore, "anno": anno, "isbn": isbn, "genere": genere, "quantita": quantita}})
    flash("✏️ Libro modificato!", "info")
    return redirect(url_for("libri"))

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
            # Usa l'ID numerico dell'utente se presente, altrimenti cerca nei movimenti esistenti
            user_id_to_save = None
            
            # Cerca l'utente nel database per vedere se ha un campo 'id' numerico
            user_doc = users_col.find_one({"_id": ObjectId(user_id)})
            
            # Prima prova con l'ID numerico dell'utente (se presente)
            if hasattr(current_user, 'original_id') and current_user.original_id is not None:
                user_id_to_save = current_user.original_id
                print(f"DEBUG: Uso original_id dell'utente: {user_id_to_save}")
            elif user_doc and "id" in user_doc:
                user_id_to_save = user_doc["id"]
                print(f"DEBUG: Trovato campo 'id' numerico nell'utente: {user_id_to_save}")
            
            # Se ancora non ha trovato, cerca nei movimenti esistenti dell'utente
            if user_id_to_save is None:
                # Cerca movimenti esistenti dell'utente corrente (prova prima come stringa)
                movimento_utente = movimenti_col.find_one({"user_id": user_id})
                
                # Se non trova, prova come numero
                if not movimento_utente:
                    try:
                        user_id_int = int(user_id) if user_id.isdigit() else None
                        if user_id_int is not None:
                            movimento_utente = movimenti_col.find_one({"user_id": user_id_int})
                    except (ValueError, AttributeError):
                        pass
                
                if movimento_utente:
                    existing_user_id = movimento_utente.get("user_id")
                    print(f"DEBUG: Movimento utente esistente con user_id: {existing_user_id} (tipo: {type(existing_user_id)})")
                    user_id_to_save = existing_user_id
                else:
                    # Se non trova movimenti, usa l'ID numerico se l'utente lo ha, altrimenti usa stringa
                    if user_doc and "id" in user_doc:
                        user_id_to_save = user_doc["id"]
                    else:
                        user_id_to_save = user_id
                    print(f"DEBUG: Nessun movimento esistente, uso user_id: {user_id_to_save} (tipo: {type(user_id_to_save)})")
            
            # Genera un nuovo ID sequenziale
            # Trova il massimo ID esistente
            max_id_doc = movimenti_col.find_one(sort=[("id", -1)])
            nuovo_id = 1
            if max_id_doc and "id" in max_id_doc:
                nuovo_id = max_id_doc["id"] + 1
                print(f"DEBUG: Massimo ID trovato: {max_id_doc['id']}, nuovo ID: {nuovo_id}")
            else:
                print(f"DEBUG: Nessun ID esistente trovato, uso ID: {nuovo_id}")
            
            movimenti_col.insert_one({
                "id": nuovo_id,
                "user_id": user_id_to_save,
                "tipo": tipo,
                "descrizione": descrizione,
                "importo": importo,
                "data": datetime.now()
            })
            print(f"DEBUG: Movimento inserito con id: {nuovo_id}, user_id: {user_id_to_save} (tipo: {type(user_id_to_save)})")
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
        print(f"DEBUG: Eliminazione movimento - ID: {elimina_id}, user_id: {user_id} (tipo: {type(user_id)})")
        
        # Prova a eliminare con user_id come stringa
        result = movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id})
        print(f"DEBUG: Tentativo 1 - user_id stringa: {result.deleted_count} documenti eliminati")
        
        # Se non trova nulla, prova anche con user_id come numero
        if result.deleted_count == 0:
            try:
                user_id_int = int(user_id) if user_id.isdigit() else None
                if user_id_int is not None:
                    result = movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id_int})
                    print(f"DEBUG: Tentativo 2 - user_id numerico ({user_id_int}): {result.deleted_count} documenti eliminati")
            except (ValueError, AttributeError) as e:
                print(f"DEBUG: Errore conversione user_id: {e}")
        
        # Se ancora non trova nulla, prova con l'ID numerico dell'utente (se presente)
        if result.deleted_count == 0:
            try:
                user_doc = users_col.find_one({"_id": ObjectId(user_id)})
                if user_doc and "id" in user_doc:
                    user_id_num = user_doc["id"]
                    result = movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id_num})
                    print(f"DEBUG: Tentativo 3 - user_id numerico dal DB ({user_id_num}): {result.deleted_count} documenti eliminati")
            except Exception as e:
                print(f"DEBUG: Errore tentativo con ID numerico: {e}")
        
        if result.deleted_count > 0:
            flash("❌ Movimento eliminato!", "danger")
        else:
            flash("❌ Errore: movimento non trovato o non autorizzato", "danger")
            print(f"DEBUG: Nessun documento eliminato. ID: {elimina_id}, user_id: {user_id}")
        
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

@app.route("/quote365")
def bet365():
    return render_template("quote365.html")
@app.route("/sitobet")
def sitobet():
    return render_template("sitobet.html")
@app.route("/kobet")
def kobet():
    return render_template("kobet.html")

@app.route("/kroosbet")
@login_required
def kroosbet():
    # Inizializza credito se non esiste
    credito = inizializza_credito_utente(current_user.id)
    return render_template("kroosbet.html", credito=credito)

def inizializza_credito_utente(user_id):
    """Inizializza il credito dell'utente se non esiste"""
    user = users_col.find_one({"_id": ObjectId(user_id)})
    if user and "credito" not in user:
        # Imposta credito iniziale di 1000€
        users_col.update_one({"_id": ObjectId(user_id)}, {"$set": {"credito": 1000.0}})
        return 1000.0
    return user.get("credito", 1000.0) if user else 1000.0

@app.route("/schedine")
@login_required
def schedine():
    """Pagina per visualizzare le schedine salvate"""
    # Inizializza credito se non esiste
    credito = inizializza_credito_utente(current_user.id)
    
    schedine_col = client["gestionale"]["schedine"]
    # Recupera solo le schedine dell'utente corrente, ordinate per data crescente
    schedine_list = list(schedine_col.find({"user_id": current_user.id}).sort("data", 1))
    
    # Converti ObjectId in stringa per il template e inizializza stato se mancante
    for s in schedine_list:
        schedina_id_obj = s["_id"]  # Salva ObjectId originale prima della conversione
        s["_id"] = str(s["_id"])
        if isinstance(s.get("data"), datetime):
            s["data_str"] = s["data"].strftime("%d/%m/%Y %H:%M")
        else:
            s["data_str"] = "Data non disponibile"
        # Inizializza stato se mancante
        if "stato" not in s:
            s["stato"] = "in_corso"
            schedine_col.update_one({"_id": schedina_id_obj}, {"$set": {"stato": "in_corso"}})
    
    return render_template("schedine.html", schedine=schedine_list, credito=credito)

@app.route("/api/leagues", methods=["GET", "POST", "OPTIONS"])
def api_leagues():
    """API endpoint per ottenere nazioni e campionati disponibili"""
    sport = request.args.get("sport", "calcio")
    
    try:
        db = client["bet365"]
        col = db[sport]
        
        # Recupera tutti i campionati unici
        leagues = col.distinct("league")
        
        # Raggruppa per nazione (estrai nazione dal nome del campionato)
        nations_leagues = {}
        for league in sorted(leagues):
            if not league:
                continue
            # Prova a estrarre la nazione dal nome del campionato
            # Esempi: "Italy - Serie A" -> "Italy", "England - Premier League" -> "England"
            parts = league.split(" - ")
            if len(parts) >= 2:
                nation = parts[0].strip()
                league_name = " - ".join(parts[1:]).strip()
            else:
                nation = "Altri"
                league_name = league
            
            if nation not in nations_leagues:
                nations_leagues[nation] = []
            nations_leagues[nation].append({
                "name": league_name,
                "full_name": league
            })
        
        return jsonify({
            "success": True,
            "nations": nations_leagues
        })
    except Exception as e:
        print(f"ERRORE API leagues: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "nations": {}
        }), 500

@app.route("/api/events")
def api_events():
    """API endpoint per ottenere gli eventi sportivi da MongoDB"""
    sport = request.args.get("sport", "calcio")
    limit = int(request.args.get("limit", 500))
    league = request.args.get("league", None)  # Filtro opzionale per campionato
    add_hour = request.args.get("add_hour", "false").lower() == "true"  # Parametro per aggiungere 1 ora
    
    try:
        db = client["bet365"]
        col = db[sport]
        
        # Costruisci query con filtro opzionale per campionato
        query = {}
        if league:
            query["league"] = league
        
        # Recupera eventi ordinati per data
        eventi = list(col.find(query).sort("start_time_date", 1).limit(limit))
        
        # Formatta l'orario (aggiungi 1 ora solo se richiesto)
        for ev in eventi:
            if "start_time_date" in ev:
                if add_hour:
                    # Aggiungi 1 ora per le altre pagine
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

@app.route("/api/salva-schedina", methods=["POST"])
@login_required
def salva_schedina():
    """Endpoint per salvare una schedina e scalare il credito"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Dati mancanti"}), 400
        
        importo = float(data.get("importo", 0))
        if importo <= 0:
            return jsonify({"success": False, "error": "Importo non valido"}), 400
        
        # Inizializza credito se non esiste
        credito_attuale = inizializza_credito_utente(current_user.id)
        
        # Verifica che ci sia credito sufficiente
        if credito_attuale < importo:
            return jsonify({
                "success": False,
                "error": f"Credito insufficiente. Credito disponibile: {credito_attuale:.2f}€"
            }), 400
        
        # Scala il credito
        nuovo_credito = credito_attuale - importo
        users_col.update_one(
            {"_id": ObjectId(current_user.id)},
            {"$set": {"credito": nuovo_credito}}
        )
        
        # Salva la schedina nel database
        schedine_col = client["gestionale"]["schedine"]
        
        schedina = {
            "scommesse": data.get("scommesse", []),
            "importo": importo,
            "vincita": float(data.get("vincita", 0)),
            "data": datetime.now(),
            "user_id": current_user.id,
            "stato": "in_corso"  # Stato di default
        }
        
        result = schedine_col.insert_one(schedina)
        
        return jsonify({
            "success": True,
            "message": "Schedina salvata con successo",
            "id": str(result.inserted_id),
            "credito_rimanente": nuovo_credito
        })
    except Exception as e:
        print(f"ERRORE salvataggio schedina: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/api/credito", methods=["GET"])
@login_required
def get_credito():
    """Endpoint per ottenere il credito dell'utente"""
    credito = inizializza_credito_utente(current_user.id)
    return jsonify({"credito": credito})

@app.route("/api/cambia-stato-schedina/<schedina_id>", methods=["POST"])
@login_required
def cambia_stato_schedina(schedina_id):
    """Endpoint per cambiare lo stato di una schedina"""
    try:
        data = request.get_json()
        nuovo_stato = data.get("stato")
        
        if nuovo_stato not in ["in_corso", "vincente", "perdente", "cancellata"]:
            return jsonify({"success": False, "error": "Stato non valido"}), 400
        
        schedine_col = client["gestionale"]["schedine"]
        
        # Verifica che la schedina appartenga all'utente corrente
        schedina = schedine_col.find_one({"_id": ObjectId(schedina_id), "user_id": current_user.id})
        if not schedina:
            return jsonify({"success": False, "error": "Schedina non trovata o non autorizzata"}), 404
        
        stato_precedente = schedina.get("stato", "in_corso")
        importo = schedina.get("importo", 0)
        vincita = schedina.get("vincita", 0)
        credito_attuale = inizializza_credito_utente(current_user.id)
        
        # Gestione transizioni di stato
        # Se diventa cancellata: restituisci l'importo
        if nuovo_stato == "cancellata" and stato_precedente != "cancellata":
            # Se era vincente, rimuovi anche la vincita che era stata aggiunta
            if stato_precedente == "vincente":
                nuovo_credito = credito_attuale - vincita + importo
            else:
                # Restituisci solo l'importo
                nuovo_credito = credito_attuale + importo
            users_col.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$set": {"credito": nuovo_credito}}
            )
        
        # Se era cancellata e ora cambia stato: rimuovi l'importo che era stato restituito
        elif stato_precedente == "cancellata" and nuovo_stato != "cancellata":
            nuovo_credito = credito_attuale - importo
            if nuovo_credito < 0:
                nuovo_credito = 0
            users_col.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$set": {"credito": nuovo_credito}}
            )
            # Se diventa anche vincente, aggiungi la vincita
            if nuovo_stato == "vincente":
                nuovo_credito = nuovo_credito + vincita
                users_col.update_one(
                    {"_id": ObjectId(current_user.id)},
                    {"$set": {"credito": nuovo_credito}}
                )
        
        # Se diventa vincente (e non era cancellata)
        elif nuovo_stato == "vincente" and stato_precedente != "vincente" and stato_precedente != "cancellata":
            nuovo_credito = credito_attuale + vincita
            users_col.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$set": {"credito": nuovo_credito}}
            )
        
        # Se era vincente e ora cambia stato (ma non diventa cancellata)
        elif stato_precedente == "vincente" and nuovo_stato != "vincente" and nuovo_stato != "cancellata":
            nuovo_credito = credito_attuale - vincita
            if nuovo_credito < 0:
                nuovo_credito = 0
            users_col.update_one(
                {"_id": ObjectId(current_user.id)},
                {"$set": {"credito": nuovo_credito}}
            )
        
        # Aggiorna lo stato della schedina
        schedine_col.update_one(
            {"_id": ObjectId(schedina_id)},
            {"$set": {"stato": nuovo_stato}}
        )
        
        return jsonify({
            "success": True,
            "message": f"Stato schedina aggiornato a {nuovo_stato}",
            "nuovo_stato": nuovo_stato
        })
    except Exception as e:
        print(f"ERRORE cambio stato schedina: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
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
            "password": generate_password_hash("password123"),
            "credito": 1000.0  # Credito iniziale
        })
    else:
        # Inizializza credito per utenti esistenti senza credito
        users_col.update_many(
            {"credito": {"$exists": False}},
            {"$set": {"credito": 1000.0}}
        )
    
    # Per Render, usa la porta da variabile d'ambiente o default
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
