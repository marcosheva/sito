from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson import ObjectId
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import bcrypt

# ===== CONFIGURAZIONE =====
MONGO_URI = "mongodb+srv://bet365odds:Aurora86@cluster0.svytet0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI)

app = Flask(__name__)
app.secret_key = "supersecretgestionale"
app.permanent_session_lifetime = timedelta(minutes=20)  # Timeout della sessione

# Abilitare CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# ===== LOGIN =====
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

users_col = client["gestionale"]["utenti"]
movimenti_col = client["gestionale"]["movimenti"]

# ===== HELPER FUNCTIONS =====
def get_user_id_for_movimenti(user_id_str):
    """Trova l'ID corretto da usare per i movimenti, gestendo compatibilità con formati vecchi"""
    user_doc = users_col.find_one({"_id": ObjectId(user_id_str)})
    
    # Prova con original_id se presente
    if hasattr(current_user, 'original_id') and current_user.original_id is not None:
        return current_user.original_id
    
    # Prova con campo 'id' numerico dell'utente
    if user_doc and "id" in user_doc:
        return user_doc["id"]
    
    # Cerca nei movimenti esistenti
    movimento_utente = movimenti_col.find_one({"user_id": user_id_str})
    if not movimento_utente:
        try:
            user_id_int = int(user_id_str) if user_id_str.isdigit() else None
            if user_id_int is not None:
                movimento_utente = movimenti_col.find_one({"user_id": user_id_int})
        except (ValueError, AttributeError):
            # Conversione fallita, continua senza questo formato
            pass
    
    if movimento_utente:
        return movimento_utente.get("user_id")
    
    # Default: usa l'ID stringa corrente
    return user_id_str

def find_movimenti_by_user_id(user_id_str):
    """Trova tutti i movimenti dell'utente, provando diversi formati per compatibilità"""
    # Prova con stringa
    movimenti = list(movimenti_col.find({"user_id": user_id_str}))
    if movimenti:
        return movimenti
    
    # Prova con numero
    try:
        user_id_int = int(user_id_str) if user_id_str.isdigit() else None
        if user_id_int is not None:
            movimenti = list(movimenti_col.find({"user_id": user_id_int}))
            if movimenti:
                return movimenti
    except (ValueError, AttributeError):
        pass
    
    # Prova con original_id
    if hasattr(current_user, 'original_id') and current_user.original_id is not None:
        try:
            movimenti = list(movimenti_col.find({"user_id": current_user.original_id}))
            if movimenti:
                return movimenti
        except Exception:
            # Fallback: continua con il prossimo tentativo
            pass
    
    # Prova con ObjectId (per compatibilità con dati vecchi)
    try:
        movimenti = list(movimenti_col.find({"user_id": ObjectId(user_id_str)}))
        if movimenti:
            return movimenti
    except Exception:
        # ObjectId non valido, continua con il prossimo tentativo
        pass
    
    # Prova con query $or (cerca tutti i formati possibili)
    try:
        query_conditions = [{"user_id": user_id_str}]
        if user_id_str.isdigit():
            query_conditions.append({"user_id": int(user_id_str)})
        try:
            query_conditions.append({"user_id": ObjectId(user_id_str)})
        except Exception:
            # ObjectId non valido, continua senza questo formato
            pass
        
        movimenti = list(movimenti_col.find({"$or": query_conditions}))
        if movimenti:
            return movimenti
    except Exception:
        # Errore nella query, nessun movimento trovato
        pass
    
    return []

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
    formato = request.form.get("formato", "")
    quantita = int(request.form["quantita"])
    col.insert_one({"nome": nome, "marca": marca, "formato": formato, "quantita": quantita})
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
    formato = request.form.get("formato", "")
    quantita = int(request.form.get("quantita", 0) or 0)
    col.update_one({"_id": ObjectId(id)}, {"$set": {"nome": nome, "marca": marca, "formato": formato, "quantita": quantita}})
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
            user_id_to_save = get_user_id_for_movimenti(user_id)
            
            # Genera un nuovo ID sequenziale
            max_id_doc = movimenti_col.find_one(sort=[("id", -1)])
            nuovo_id = 1
            if max_id_doc and "id" in max_id_doc:
                nuovo_id = max_id_doc["id"] + 1
            
            movimenti_col.insert_one({
                "id": nuovo_id,
                "user_id": user_id_to_save,
                "tipo": tipo,
                "descrizione": descrizione,
                "importo": importo,
                "data": datetime.now()
            })
            flash("✅ Movimento inserito con successo", "success")
            return redirect(url_for("gestionale"))
        elif azione == "modifica":
            mov_id = request.form.get("id")
            user_id_to_check = get_user_id_for_movimenti(user_id)
            
            # Prova a modificare con diversi formati di user_id
            result = movimenti_col.update_one(
                {"_id": ObjectId(mov_id), "user_id": user_id},
                {"$set": {"tipo": tipo, "descrizione": descrizione, "importo": importo}}
            )
            
            if result.matched_count == 0:
                try:
                    user_id_int = int(user_id) if user_id.isdigit() else None
                    if user_id_int is not None:
                        result = movimenti_col.update_one(
                            {"_id": ObjectId(mov_id), "user_id": user_id_int},
                            {"$set": {"tipo": tipo, "descrizione": descrizione, "importo": importo}}
                        )
                except (ValueError, AttributeError):
                    pass
            
            if result.matched_count == 0 and user_id_to_check != user_id:
                result = movimenti_col.update_one(
                    {"_id": ObjectId(mov_id), "user_id": user_id_to_check},
                        {"$set": {"tipo": tipo, "descrizione": descrizione, "importo": importo}}
                    )
            
            if result.matched_count > 0:
                flash("✏️ Movimento modificato con successo", "info")
            else:
                flash("❌ Errore: movimento non trovato o non autorizzato", "danger")
            
            return redirect(url_for("gestionale"))

    # Eliminazione movimento
    elimina_id = request.args.get("elimina")
    if elimina_id:
        user_id_to_check = get_user_id_for_movimenti(user_id)
        
        result = movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id})
        
        if result.deleted_count == 0:
            try:
                user_id_int = int(user_id) if user_id.isdigit() else None
                if user_id_int is not None:
                    result = movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id_int})
            except (ValueError, AttributeError):
                pass
        
        if result.deleted_count == 0 and user_id_to_check != user_id:
            result = movimenti_col.delete_one({"_id": ObjectId(elimina_id), "user_id": user_id_to_check})
        
        if result.deleted_count > 0:
            flash("❌ Movimento eliminato!", "danger")
        else:
            flash("❌ Errore: movimento non trovato o non autorizzato", "danger")
        
        return redirect(url_for("gestionale"))

    # Lista movimenti e saldo
    try:
        movimenti = find_movimenti_by_user_id(user_id)
        # Ordina per data (se presente) o per _id
        if movimenti:
            movimenti.sort(key=lambda x: x.get("data") if x.get("data") else x.get("_id"), reverse=True)
    except Exception:
        # Errore nel caricamento movimenti, restituisci lista vuota
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
            stored_password = user["password"]
            
            # Se è bytes, convertila in stringa
            if isinstance(stored_password, bytes):
                try:
                    stored_password = stored_password.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        stored_password = stored_password.decode('latin-1')
                    except Exception:
                        return jsonify({"success": False, "message": "Errore nel formato della password memorizzata"}), 500
                
                # Aggiorna il database con la stringa invece dei bytes
                users_col.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"password": stored_password}}
                )
            
            # Verifica che la password memorizzata sia valida
            if not stored_password or not isinstance(stored_password, str):
                return jsonify({"success": False, "message": "Password memorizzata non valida"}), 500
            
            # Pulisci la password da eventuali caratteri nascosti o whitespace
            original_password = stored_password
            stored_password = stored_password.strip()
            stored_password = ''.join(char for char in stored_password if char.isprintable() or char in ['\n', '\r', '\t'])
            stored_password = stored_password.strip()
            
            if len(stored_password) < 20:
                return jsonify({"success": False, "message": "Password memorizzata non valida (troncata?)"}), 500
            
            # Se la password è stata pulita, aggiorna il database
            if stored_password != original_password:
                users_col.update_one(
                    {"_id": user["_id"]},
                    {"$set": {"password": stored_password}}
                )
            
            # Verifica password
            password_valid = False
            try:
                password_valid = check_password_hash(stored_password, password)
            except ValueError as e:
                # Fallback: prova con bcrypt direttamente se l'hash sembra essere bcrypt
                if stored_password.startswith('$2'):
                    try:
                        stored_password_bytes = stored_password.encode('utf-8') if isinstance(stored_password, str) else stored_password
                        password_valid = bcrypt.checkpw(password.encode('utf-8'), stored_password_bytes)
                        
                        # Se funziona, rigenera la password con werkzeug per compatibilità futura
                        if password_valid:
                            new_hash = generate_password_hash(password)
                            users_col.update_one(
                                {"_id": user["_id"]},
                                {"$set": {"password": new_hash}}
                            )
                    except Exception:
                        return jsonify({"success": False, "message": f"Errore nel formato della password: {str(e)}. La password nel database potrebbe essere corrotta."}), 500
                else:
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

@app.route("/betbet")
@login_required
def betbet():
    # Inizializza credito se non esiste
    credito = inizializza_credito_utente(current_user.id)
    return render_template("betbet.html", credito=credito)

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
    
    # Mappatura nazioni (inglese -> italiano) - solo per traduzione
    nation_mapping = {
        "Italy": "Italia",
        "Argentina": "Argentina",
        "Australia": "Australia",
        "Austria": "Austria",
        "Brazil": "Brasile",
        "Bulgaria": "Bulgaria",
        "China": "Cina",
        "Denmark": "Danimarca",
        "Ecuador": "Ecuador",
        "England": "Inghilterra",
        "France": "Francia",
        "Germany": "Germania",
        "Greece": "Grecia",
        "Israel": "Israele",
        "Netherlands": "Paesi Bassi",
        "Paraguay": "Paraguay",
        "Poland": "Polonia",
        "Slovenia": "Slovenia",
        "Spain": "Spagna"
    }
    
    try:
        db = client["bet365"]
        col = db[sport]
        
        # Recupera tutti i campionati unici
        leagues = col.distinct("league")
        
        # SEMPLICE: prima parola = nazione, resto = nome campionato
        nations_leagues = {}
        for league in sorted(leagues):
            if not league:
                continue
            
            # Se c'è " - ", usa quello come separatore
            if " - " in league:
                parts = league.split(" - ", 1)
                nation_raw = parts[0].strip()
                league_name = parts[1].strip() if len(parts) > 1 else ""
            else:
                # Altrimenti: prima parola = nazione, resto = campionato
                words = league.split()
                if len(words) < 2:
                    # Se ha solo una parola, usa quella come nazione e nome vuoto
                    nation_raw = words[0] if words else "Altri"
                    league_name = ""
                else:
                    # Caso speciale: "Bosnia & Herzegovina"
                    if words[0] == "Bosnia" and len(words) >= 3 and words[1] == "&":
                        nation_raw = "Bosnia & Herzegovina"
                        league_name = " ".join(words[3:])
                    else:
                        # Prima parola = nazione, resto = campionato
                        nation_raw = words[0]
                        league_name = " ".join(words[1:])
            
            # Applica mappatura per traduzione (se esiste)
            nation = nation_mapping.get(nation_raw, nation_raw)
            
            # Se il nome del campionato è vuoto, usa il full_name
            if not league_name:
                league_name = league
            
            if nation not in nations_leagues:
                nations_leagues[nation] = []
            nations_leagues[nation].append({
                "name": league_name,
                "full_name": league
            })
        
        # Rimuovi "Altri" se esiste e ha campionati
        if "Altri" in nations_leagues:
            del nations_leagues["Altri"]
        
        # Ordina: prima Italia, poi altre alfabeticamente
        sorted_nations = sorted(nations_leagues.keys(), key=lambda x: (x != "Italia", x))
        ordered_nations = {nation: nations_leagues[nation] for nation in sorted_nations}
        
        return jsonify({
            "success": True,
            "nations": ordered_nations
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "nations": {}
        }), 500

@app.route("/api/leagues-betbet", methods=["GET", "POST", "OPTIONS"])
def api_leagues_betbet():
    """API endpoint per ottenere nazioni e campionati dal database 'sports' (formato BetsAPI)"""
    sport = request.args.get("sport", "calcio")
    
    # Mappatura nazioni (inglese -> italiano)
    nation_mapping = {
        "Italy": "Italia",
        "Argentina": "Argentina",
        "Australia": "Australia",
        "Austria": "Austria",
        "Brazil": "Brasile",
        "Bulgaria": "Bulgaria",
        "China": "Cina",
        "Denmark": "Danimarca",
        "Ecuador": "Ecuador",
        "England": "Inghilterra",
        "France": "Francia",
        "Germany": "Germania",
        "Greece": "Grecia",
        "Israel": "Israele",
        "Netherlands": "Paesi Bassi",
        "Paraguay": "Paraguay",
        "Poland": "Polonia",
        "Slovenia": "Slovenia",
        "Spain": "Spagna"
    }
    
    # Mappa sport UI -> sport_id BetsAPI
    sport_id_map = {
        'calcio': '1', 'basket': '18', 'tennis': '13', 'hockey': '17',
        'baseball': '16', 'pallamano': '78', 'freccette': '15', 'pingpong': '92',
        'rugby': '8', 'futsal': '83', 'volleyball': '91', 'pallanuoto': '110',
        'football': '12', 'boxing': '9', 'E-Sport': '151', 'Badminton': '94',
        'Cricket': '3', 'Squash': '107', 'Horse Racing': '2'
    }
    sport_id = sport_id_map.get(sport, '1')
    
    try:
        db = client["sports"]
        col = db["prematch"]
        
        # Query per il sport specifico
        query = {"sport_id": sport_id, "settled": False}
        
        # Recupera tutti i campionati unici iterando sui documenti
        # Questo approccio è più robusto e gestisce diversi formati
        # Usa (league_name, nation) come chiave per distinguere campionati con stesso nome ma nazioni diverse
        leagues_seen = set()  # Set di tuple (league_name, nation) per evitare duplicati
        league_nation_counts = {}  # {league_name: {nation: count}} per dedurre la nazione più comune
        
        # Prima passata: raccogli tutti i campionati e conta le nazioni
        for doc in col.find(query, {"league": 1, "nation": 1}):
            league_name = None
            nation_raw = doc.get("nation", "Altri")
            
            # Estrai il nome del campionato
            league = doc.get("league")
            if isinstance(league, dict):
                league_name = league.get("name")
            elif isinstance(league, str):
                league_name = league
            
            if not league_name:
                continue
            
            # Se nation è vuoto, prova a estrarlo dal league se è un oggetto
            if not nation_raw or nation_raw == "Altri":
                if isinstance(league, dict) and "nation" in league:
                    nation_raw = league["nation"]
            
            # Se ancora vuoto o "Altri", prova a dedurre dal nome del campionato
            if not nation_raw or nation_raw == "Altri":
                league_lower = league_name.lower()
                # Deduzione nazione dal nome del campionato
                if "brazil" in league_lower or "brasil" in league_lower:
                    nation_raw = "Brazil"
                elif "italy" in league_lower or "italia" in league_lower:
                    nation_raw = "Italy"
                elif "spain" in league_lower or "spagna" in league_lower:
                    nation_raw = "Spain"
                elif "england" in league_lower or "inghilterra" in league_lower:
                    nation_raw = "England"
                elif "france" in league_lower or "francia" in league_lower:
                    nation_raw = "France"
                elif "germany" in league_lower or "germania" in league_lower:
                    nation_raw = "Germany"
            
            # Conta le nazioni per ogni campionato (per dedurre la nazione più comune)
            if league_name not in league_nation_counts:
                league_nation_counts[league_name] = {}
            if nation_raw and nation_raw != "Altri":
                league_nation_counts[league_name][nation_raw] = league_nation_counts[league_name].get(nation_raw, 0) + 1
            
            # Salva la combinazione (league_name, nation) se abbiamo una nazione valida
            if nation_raw and nation_raw != "Altri":
                leagues_seen.add((league_name, nation_raw))
        
        # Seconda passata: per i campionati che non abbiamo ancora visto con nazione valida,
        # usa la nazione più comune se disponibile
        # Prima raccogliamo tutte le combinazioni (league_name, nation) che abbiamo visto
        leagues_by_name = {}  # {league_name: [nations]}
        for league_name, nation_raw in leagues_seen:
            if league_name not in leagues_by_name:
                leagues_by_name[league_name] = []
            leagues_by_name[league_name].append(nation_raw)
        
        # Per ogni campionato che abbiamo visto, se ha più nazioni, le includiamo tutte
        # Se un campionato non è stato visto con nazione valida, usa la più comune
        final_leagues = set()
        for league_name in league_nation_counts:
            if league_name in leagues_by_name:
                # Aggiungi tutte le nazioni trovate per questo campionato
                for nation in leagues_by_name[league_name]:
                    final_leagues.add((league_name, nation))
            else:
                # Se non abbiamo visto questo campionato con nazione valida, usa la più comune
                counts = league_nation_counts[league_name]
                if counts:
                    most_common_nation = max(counts.items(), key=lambda x: x[1])[0]
                    final_leagues.add((league_name, most_common_nation))
        
        # Aggiungi anche i campionati che abbiamo visto direttamente
        final_leagues.update(leagues_seen)
        
        # Organizza per nazione
        nations_leagues = {}
        for league_name, nation_raw in final_leagues:
            # Applica mappatura per traduzione (se esiste), altrimenti usa il nome originale
            # Questo assicura che TUTTE le nazioni vengano incluse, anche quelle non mappate
            nation = nation_mapping.get(nation_raw, nation_raw)
            
            # Se la nazione è ancora "Altri" o vuota, prova a dedurla dal nome del campionato
            if not nation or nation == "Altri":
                # Prova a dedurre la nazione dal nome del campionato (es. "Brazil Serie A" -> "Brasile")
                if "brazil" in league_name.lower() or "brasil" in league_name.lower():
                    nation = "Brasile"
                elif "italy" in league_name.lower() or "italia" in league_name.lower():
                    nation = "Italia"
                elif "spain" in league_name.lower() or "spagna" in league_name.lower():
                    nation = "Spagna"
                elif "england" in league_name.lower() or "inghilterra" in league_name.lower():
                    nation = "Inghilterra"
                elif "france" in league_name.lower() or "francia" in league_name.lower():
                    nation = "Francia"
                elif "germany" in league_name.lower() or "germania" in league_name.lower():
                    nation = "Germania"
                else:
                    # Se non riesci a dedurla, usa il nome originale o "Altri"
                    nation = nation_raw if nation_raw else "Altri"
            
            if nation not in nations_leagues:
                nations_leagues[nation] = []
            
            # Evita duplicati
            if not any(l["name"] == league_name for l in nations_leagues[nation]):
                nations_leagues[nation].append({
                    "name": league_name,
                    "full_name": league_name
                })
        
        # Ordina i campionati per nome
        for nation in nations_leagues:
            nations_leagues[nation].sort(key=lambda x: x["name"])
        
        # NON rimuovere "Altri" - includi tutte le nazioni
        # Se "Altri" esiste, mantienila nella lista
        
        # Ordina: prima Italia, poi altre alfabeticamente
        sorted_nations = sorted(nations_leagues.keys(), key=lambda x: (x != "Italia", x))
        ordered_nations = {nation: nations_leagues[nation] for nation in sorted_nations}
        
        return jsonify({
            "success": True,
            "nations": ordered_nations
        })
    except Exception as e:
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
        return jsonify({
            "success": False,
            "error": str(e),
            "results": []
        }), 500

@app.route("/api/search", methods=["GET"])
def api_search():
    """API endpoint per cercare eventi direttamente nel database (più veloce)"""
    sport = request.args.get("sport", "calcio")
    query = request.args.get("q", "").strip()
    limit = int(request.args.get("limit", 50))  # Limite più basso per la ricerca
    
    if not query:
        return jsonify({
            "success": False,
            "error": "Query vuota",
            "results": []
        }), 400
    
    try:
        db = client["bet365"]
        col = db[sport]
        
        # Crea query MongoDB per cercare in vari campi
        search_query = {
            "$or": [
                {"match_id": {"$regex": query, "$options": "i"}},
                {"home_name": {"$regex": query, "$options": "i"}},
                {"away_name": {"$regex": query, "$options": "i"}},
                {"league": {"$regex": query, "$options": "i"}},
                {"numero_corsa": {"$regex": query, "$options": "i"}}
            ]
        }
        
        # Cerca anche per match esatto dell'ID (se è un numero)
        if query.isdigit():
            search_query["$or"].append({"match_id": query})
            try:
                search_query["$or"].append({"match_id": int(query)})
            except ValueError:
                pass
        
        # Recupera eventi ordinati per data
        eventi = list(col.find(search_query).sort("start_time_date", 1).limit(limit))
        
        # Formatta l'orario
        for ev in eventi:
            if "start_time_date" in ev:
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
        return jsonify({
            "success": False,
            "error": str(e),
            "results": []
        }), 500

@app.route("/api/events-betbet")
def api_events_betbet():
    """API endpoint per ottenere gli eventi sportivi da MongoDB database 'sports' (formato BetsAPI)"""
    sport = request.args.get("sport", "calcio")
    limit = int(request.args.get("limit", 500))
    league = request.args.get("league", None)
    nation = request.args.get("nation", None)
    
    # Mappatura nazioni (italiano -> inglese per query)
    nation_reverse_mapping = {
        "Italia": "Italy",
        "Argentina": "Argentina",
        "Australia": "Australia",
        "Austria": "Austria",
        "Brasile": "Brazil",
        "Bulgaria": "Bulgaria",
        "Cina": "China",
        "Danimarca": "Denmark",
        "Ecuador": "Ecuador",
        "Inghilterra": "England",
        "Francia": "France",
        "Germania": "Germany",
        "Grecia": "Greece",
        "Israele": "Israel",
        "Paesi Bassi": "Netherlands",
        "Paraguay": "Paraguay",
        "Polonia": "Poland",
        "Slovenia": "Slovenia",
        "Spagna": "Spain"
    }
    
    # Mappa sport UI -> sport_id BetsAPI
    sport_id_map = {
        'calcio': '1', 'basket': '18', 'tennis': '13', 'hockey': '17',
        'baseball': '16', 'pallamano': '78', 'freccette': '15', 'pingpong': '92',
        'rugby': '8', 'futsal': '83', 'volleyball': '91', 'pallanuoto': '110',
        'football': '12', 'boxing': '9', 'E-Sport': '151', 'Badminton': '94',
        'Cricket': '3', 'Squash': '107', 'Horse Racing': '2'
    }
    sport_id = sport_id_map.get(sport, '1')
    
    try:
        db = client["sports"]
        col = db["prematch"]
        
        # Costruisci query
        query = {"sport_id": sport_id, "settled": False}
        if league:
            query["league.name"] = league
        # Aggiungi filtro per nazione se fornito (per evitare ambiguità con campionati omonimi)
        if nation:
            # Converti nazione italiana in inglese se necessario
            nation_english = nation_reverse_mapping.get(nation, nation)
            query["nation"] = nation_english
        
        # Recupera eventi ordinati per time
        eventi_raw = list(col.find(query).sort("time", 1).limit(limit))
        
        # Converti formato BetsAPI -> formato betbet
        eventi = []
        for ev in eventi_raw:
            # Converti formato
            evento_convertito = {
                "match_id": str(ev.get("id", "")),
                "home_name": ev.get("home", {}).get("name", "") if isinstance(ev.get("home"), dict) else "",
                "away_name": ev.get("away", {}).get("name", "") if isinstance(ev.get("away"), dict) else "",
                "league": ev.get("league", {}).get("name", "") if isinstance(ev.get("league"), dict) else ev.get("league", ""),
                "sport": sport,
                "nation": ev.get("nation", ""),
                "quote": {},
                "quote_1x2": {"1": None, "X": None, "2": None}
            }
            
            # Converti time in start_time_date e start_time
            if "time" in ev:
                try:
                    time_int = int(ev["time"])
                    evento_convertito["start_time_date"] = datetime.fromtimestamp(time_int, tz=timezone.utc)
                    evento_convertito["start_time"] = evento_convertito["start_time_date"].strftime("%Y-%m-%d %H:%M:%S")
                except:
                    evento_convertito["start_time"] = str(ev.get("time", ""))
            
            # Converti markets in quote
            if "markets" in ev and ev["markets"]:
                markets = ev["markets"]
                quote = {}
                
                # 1x2 -> full_time_result
                if "1x2" in markets and markets["1x2"]:
                    quote["full_time_result"] = markets["1x2"]
                    # Estrai quote_1x2
                    for item in markets["1x2"]:
                        if isinstance(item, dict):
                            name = (item.get("name") or item.get("header") or "").strip().lower()
                            odds = item.get("odds")
                            if name == "1" or name == "home":
                                evento_convertito["quote_1x2"]["1"] = odds
                            elif name == "x" or name == "draw" or name == "pareggio":
                                evento_convertito["quote_1x2"]["X"] = odds
                            elif name == "2" or name == "away":
                                evento_convertito["quote_1x2"]["2"] = odds
                
                # uo -> goals_over_under
                if "uo" in markets and markets["uo"]:
                    quote["goals_over_under"] = markets["uo"]
                
                # ggng -> both_teams_to_score
                if "ggng" in markets and markets["ggng"]:
                    quote["both_teams_to_score"] = markets["ggng"]
                
                # Aggiungi tutti gli altri markets
                for key, value in markets.items():
                    if key not in ["1x2", "uo", "ggng"]:
                        quote[key] = value
                
                evento_convertito["quote"] = quote
            
            # Aggiungi dati goalscorer dalla collezione 'players'
            try:
                players_col = db["players"]
                players_doc = players_col.find_one({"id": str(ev.get("id", ""))})
                if players_doc and "odds" in players_doc:
                    # Rimuovi _id per evitare errori di serializzazione JSON
                    if "_id" in players_doc:
                        del players_doc["_id"]
                    evento_convertito["players"] = players_doc
            except Exception as e:
                # Ignora errori nel recupero dei players
                pass
            
            # Aggiungi quote calcolate dalla collezione 'calculated'
            try:
                calculated_col = db["calculated"]
                calculated_doc = calculated_col.find_one({"id": str(ev.get("id", ""))})
                if calculated_doc and "odds" in calculated_doc:
                    calculated_odds = calculated_doc["odds"]
                    
                    # Mappa le quote calcolate al formato quote
                    if not evento_convertito.get("quote"):
                        evento_convertito["quote"] = {}
                    
                    # Mappatura chiavi calculated -> quote (tutti i mercati dal JSON)
                    calculated_mapping = {
                        # Over/Under Gol
                        "uo": "goals_over_under",
                        "uo_1t": "1st_half_goals_over_under",
                        "uo_2t": "2nd_half_goals_over_under",
                        "uo_home": "home_team_goals_over_under",  # O/U C/O finale
                        "uo_away": "away_team_goals_over_under",  # O/U C/O finale
                        "uo_1t_home": "1st_half_home_team_goals_over_under",  # O/U 1T C/O
                        "uo_1t_away": "1st_half_away_team_goals_over_under",  # O/U 1T C/O
                        "uo_2t_home": "2nd_half_home_team_goals_over_under",  # O/U 2T C/O
                        "uo_2t_away": "2nd_half_away_team_goals_over_under",  # O/U 2T C/O
                        "uo_special": "goals_over_under_special",
                        # Alternative keys per O/U C/O
                        "home_team_total_goals": "home_team_total_goals",
                        "away_team_total_goals": "away_team_total_goals",
                        "team_total_goals": "team_total_goals",
                        "1st_half_team_total_goals": "1st_half_team_total_goals",
                        "2nd_half_team_total_goals": "2nd_half_team_total_goals",
                        
                        # 1X2 e Doppia Chance
                        "1x2": "full_time_result",
                        "dc": "double_chance",
                        "1x2_1t": "half_time_result",
                        "1x2_2t": "2nd_half_result",
                        "dc_1t": "half_time_double_chance",
                        "dc_2t": "2nd_half_double_chance",
                        "1t_ft": "half_time_full_time",
                        "dc_1t_ft": "half_time_full_time_double_chance",
                        
                        # First/Last Goal
                        "first_goal": "first_team_to_score",
                        "last_goal": "last_team_to_score",
                        
                        # Early/Late Goal
                        "early_goal": "early_goal",
                        "late_goal": "late_goal",
                        
                        # Corners
                        "crn_uo": "corners_over_under",
                        "crn_uo_1t": "1st_half_corners_over_under",
                        "crn_uo_3": "corners_over_under_3way",
                        "corner_multi": "corners_multi",
                        "crn_odd_even": "corners_odd_even",
                        "crn_odd_even_1t": "1st_half_corners_odd_even",
                        "crn_odd_even_home": "corners_odd_even_home",
                        "crn_odd_even_away": "corners_odd_even_away",
                        "crn_odd_even_1t_home": "1st_half_corners_odd_even_home",
                        "crn_odd_even_1t_away": "1st_half_corners_odd_even_away",
                        
                        # Cards
                        "crd_uo": "cards_over_under",
                        "crd_1x2": "cards_1x2",
                        
                        # Total Goals
                        "tg": "total_goals",
                        "tg_1t": "1st_half_total_goals",
                        "tg_2t": "2nd_half_total_goals",
                        "tg_home": "home_team_total_goals",
                        "tg_away": "away_team_total_goals",
                        "alternative_total_goals": "alternative_total_goals",
                        "1st_half_alternative_total_goals": "1st_half_alternative_total_goals",
                        "2nd_half_alternative_total_goals": "2nd_half_alternative_total_goals",
                        
                        # Odd/Even
                        "odd_even": "goals_odd_even",
                        "odd_even_1t": "1st_half_goals_odd_even",
                        "odd_even_2t": "2nd_half_goals_odd_even",
                        "team_goals_odd_even": "team_goals_odd_even",
                        
                        # Correct Score
                        "cs": "correct_score",
                        "cs_1t": "1st_half_correct_score",
                        "cs_2t": "2nd_half_correct_score",
                        "cs_ht_ft": "half_time_full_time_correct_score",
                        
                        # Draw No Bet
                        "dnb": "draw_no_bet",
                        "dnb_1t": "1st_half_draw_no_bet",
                        "dnb_2t": "2nd_half_draw_no_bet",
                        
                        # Handicap
                        "handicap": "handicap_result",
                        "handicap_1t": "1st_half_handicap_result",
                        "handicap_2t": "2nd_half_handicap_result",
                        "asian_handicap": "asian_handicap",
                        
                        # Handicap No Bet
                        "hnb": "handicap_no_bet",
                        "hnb_1t": "1st_half_handicap_no_bet",
                        "hnb_2t": "2nd_half_handicap_no_bet",
                        
                        # Asian No Bet
                        "anb": "asian_no_bet",
                        "anb_1t": "1st_half_asian_no_bet",
                        "anb_2t": "2nd_half_asian_no_bet",
                        
                        # Goal No Bet
                        "gnb": "goal_no_bet",
                        
                        # Half More Goals
                        "half_more_goals": "half_more_goals",
                        
                        # Combo Markets
                        "comboDc1tOu": "combo_double_chance_1t_over_under",
                        "comboDc2tOu": "combo_double_chance_2t_over_under",
                        "combo_dc_multi": "combo_double_chance_multi",
                        
                        # Multi Goals
                        "multigol": "multi_goals",
                        "multi1t": "multi_goals_1t",
                        "multi2t": "multi_goals_2t",
                        "multi1t_ft": "multi_goals_1t_full_time",
                        "match_goals_range": "match_goals_range",
                        "1st_half_match_goals_range": "1st_half_match_goals_range",
                        "2nd_half_match_goals_range": "2nd_half_match_goals_range",
                        "home_team_match_goals_range": "home_team_match_goals_range",
                        "away_team_match_goals_range": "away_team_match_goals_range",
                        "match_goals_range_corners": "match_goals_range_corners",
                        "1st_half_2nd_half_match_goals_range": "1st_half_2nd_half_match_goals_range",
                        
                        # Special Markets
                        "home_score_1_2": "home_score_1_2",
                        "away_score_1_2": "away_score_1_2",
                        "home_wins_both": "home_wins_both_halves",
                        "away_wins_both": "away_wins_both_halves",
                        "home_or_away_win_both": "home_or_away_win_both_halves",
                        "home_win_at_least_one": "home_win_at_least_one_half",
                        "away_win_at_least_one": "away_win_at_least_one_half",
                        "wins_from_behind": "wins_from_behind",
                        "combo_1x2_first_goal": "combo_1x2_first_goal"
                    }
                    
                    # Aggiungi tutte le quote calcolate (con mappatura se disponibile)
                    for calc_key, calc_value in calculated_odds.items():
                        if isinstance(calc_value, list):
                            # Usa la mappatura se disponibile, altrimenti usa la chiave originale
                            quote_key = calculated_mapping.get(calc_key, calc_key)
                            evento_convertito["quote"][quote_key] = calc_value
                            
                            # Se è 1x2_1t o 1x2_2t, aggiorna anche quote_1x2 se necessario
                            if calc_key == "1x2_1t" and not evento_convertito["quote_1x2"]["1"]:
                                for item in calc_value:
                                    if isinstance(item, dict):
                                        header = (item.get("header") or "").strip()
                                        odds = item.get("odds")
                                        if header == "1":
                                            evento_convertito["quote_1x2"]["1"] = odds
                                        elif header == "X":
                                            evento_convertito["quote_1x2"]["X"] = odds
                                        elif header == "2":
                                            evento_convertito["quote_1x2"]["2"] = odds
            except Exception as calc_error:
                # Ignora errori nella lettura delle quote calcolate
                pass
            
            # Converti ObjectId in stringa
            if "_id" in ev:
                evento_convertito["_id"] = str(ev["_id"])
            
            eventi.append(evento_convertito)
        
        return jsonify({
            "success": True,
            "results": eventi,
            "count": len(eventi)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "results": []
        }), 500

@app.route("/api/search-betbet", methods=["GET"])
def api_search_betbet():
    """API endpoint per cercare eventi nel database 'sports' (formato BetsAPI)"""
    sport = request.args.get("sport", "calcio")
    query = request.args.get("q", "").strip()
    limit = int(request.args.get("limit", 50))
    
    if not query:
        return jsonify({
            "success": False,
            "error": "Query vuota",
            "results": []
        }), 400
    
    # Mappa sport UI -> sport_id BetsAPI
    sport_id_map = {
        'calcio': '1', 'basket': '18', 'tennis': '13', 'hockey': '17',
        'baseball': '16', 'pallamano': '78', 'freccette': '15', 'pingpong': '92',
        'rugby': '8', 'futsal': '83', 'volleyball': '91', 'pallanuoto': '110',
        'football': '12', 'boxing': '9', 'E-Sport': '151', 'Badminton': '94',
        'Cricket': '3', 'Squash': '107', 'Horse Racing': '2'
    }
    sport_id = sport_id_map.get(sport, '1')
    
    try:
        db = client["sports"]
        col = db["prematch"]
        
        # Crea query MongoDB
        search_query = {
            "sport_id": sport_id,
            "settled": False,
            "$or": [
                {"id": {"$regex": query, "$options": "i"}},
                {"home.name": {"$regex": query, "$options": "i"}},
                {"away.name": {"$regex": query, "$options": "i"}},
                {"league.name": {"$regex": query, "$options": "i"}}
            ]
        }
        
        # Cerca anche per match esatto dell'ID
        if query.isdigit():
            search_query["$or"].append({"id": query})
            try:
                search_query["$or"].append({"id": int(query)})
            except ValueError:
                pass
        
        # Recupera eventi
        eventi_raw = list(col.find(search_query).sort("time", 1).limit(limit))
        
        # Converti formato (stessa logica di api_events_betbet)
        eventi = []
        for ev in eventi_raw:
            evento_convertito = {
                "match_id": str(ev.get("id", "")),
                "home_name": ev.get("home", {}).get("name", "") if isinstance(ev.get("home"), dict) else "",
                "away_name": ev.get("away", {}).get("name", "") if isinstance(ev.get("away"), dict) else "",
                "league": ev.get("league", {}).get("name", "") if isinstance(ev.get("league"), dict) else ev.get("league", ""),
                "sport": sport,
                "nation": ev.get("nation", ""),
                "quote": {},
                "quote_1x2": {"1": None, "X": None, "2": None}
            }
            
            if "time" in ev:
                try:
                    time_int = int(ev["time"])
                    evento_convertito["start_time_date"] = datetime.fromtimestamp(time_int, tz=timezone.utc)
                    evento_convertito["start_time"] = evento_convertito["start_time_date"].strftime("%Y-%m-%d %H:%M:%S")
                except:
                    evento_convertito["start_time"] = str(ev.get("time", ""))
            
            if "markets" in ev and ev["markets"]:
                markets = ev["markets"]
                quote = {}
                
                if "1x2" in markets and markets["1x2"]:
                    quote["full_time_result"] = markets["1x2"]
                    for item in markets["1x2"]:
                        if isinstance(item, dict):
                            name = (item.get("name") or item.get("header") or "").strip().lower()
                            odds = item.get("odds")
                            if name == "1" or name == "home":
                                evento_convertito["quote_1x2"]["1"] = odds
                            elif name == "x" or name == "draw" or name == "pareggio":
                                evento_convertito["quote_1x2"]["X"] = odds
                            elif name == "2" or name == "away":
                                evento_convertito["quote_1x2"]["2"] = odds
                
                if "uo" in markets and markets["uo"]:
                    quote["goals_over_under"] = markets["uo"]
                
                if "ggng" in markets and markets["ggng"]:
                    quote["both_teams_to_score"] = markets["ggng"]
                
                for key, value in markets.items():
                    if key not in ["1x2", "uo", "ggng"]:
                        quote[key] = value
                
                evento_convertito["quote"] = quote
            
            # Aggiungi dati goalscorer dalla collezione 'players'
            try:
                players_col = db["players"]
                players_doc = players_col.find_one({"id": str(ev.get("id", ""))})
                if players_doc and "odds" in players_doc:
                    # Rimuovi _id per evitare errori di serializzazione JSON
                    if "_id" in players_doc:
                        del players_doc["_id"]
                    evento_convertito["players"] = players_doc
            except Exception as e:
                # Ignora errori nel recupero dei players
                pass
            
            # Aggiungi quote calcolate dalla collezione 'calculated'
            try:
                calculated_col = db["calculated"]
                calculated_doc = calculated_col.find_one({"id": str(ev.get("id", ""))})
                if calculated_doc and "odds" in calculated_doc:
                    calculated_odds = calculated_doc["odds"]
                    
                    # Mappa le quote calcolate al formato quote
                    if not evento_convertito.get("quote"):
                        evento_convertito["quote"] = {}
                    
                    # Mappatura chiavi calculated -> quote (tutti i mercati dal JSON)
                    calculated_mapping = {
                        # Over/Under Gol
                        "uo": "goals_over_under",
                        "uo_1t": "1st_half_goals_over_under",
                        "uo_2t": "2nd_half_goals_over_under",
                        "uo_home": "home_team_goals_over_under",  # O/U C/O finale
                        "uo_away": "away_team_goals_over_under",  # O/U C/O finale
                        "uo_1t_home": "1st_half_home_team_goals_over_under",  # O/U 1T C/O
                        "uo_1t_away": "1st_half_away_team_goals_over_under",  # O/U 1T C/O
                        "uo_2t_home": "2nd_half_home_team_goals_over_under",  # O/U 2T C/O
                        "uo_2t_away": "2nd_half_away_team_goals_over_under",  # O/U 2T C/O
                        "uo_special": "goals_over_under_special",
                        # Alternative keys per O/U C/O
                        "home_team_total_goals": "home_team_total_goals",
                        "away_team_total_goals": "away_team_total_goals",
                        "team_total_goals": "team_total_goals",
                        "1st_half_team_total_goals": "1st_half_team_total_goals",
                        "2nd_half_team_total_goals": "2nd_half_team_total_goals",
                        
                        # 1X2 e Doppia Chance
                        "1x2": "full_time_result",
                        "dc": "double_chance",
                        "1x2_1t": "half_time_result",
                        "1x2_2t": "2nd_half_result",
                        "dc_1t": "half_time_double_chance",
                        "dc_2t": "2nd_half_double_chance",
                        "1t_ft": "half_time_full_time",
                        "dc_1t_ft": "half_time_full_time_double_chance",
                        
                        # First/Last Goal
                        "first_goal": "first_team_to_score",
                        "last_goal": "last_team_to_score",
                        
                        # Early/Late Goal
                        "early_goal": "early_goal",
                        "late_goal": "late_goal",
                        
                        # Corners
                        "crn_uo": "corners_over_under",
                        "crn_uo_1t": "1st_half_corners_over_under",
                        "crn_uo_3": "corners_over_under_3way",
                        "corner_multi": "corners_multi",
                        "crn_odd_even": "corners_odd_even",
                        "crn_odd_even_1t": "1st_half_corners_odd_even",
                        "crn_odd_even_home": "corners_odd_even_home",
                        "crn_odd_even_away": "corners_odd_even_away",
                        "crn_odd_even_1t_home": "1st_half_corners_odd_even_home",
                        "crn_odd_even_1t_away": "1st_half_corners_odd_even_away",
                        
                        # Cards
                        "crd_uo": "cards_over_under",
                        "crd_1x2": "cards_1x2",
                        
                        # Total Goals
                        "tg": "total_goals",
                        "tg_1t": "1st_half_total_goals",
                        "tg_2t": "2nd_half_total_goals",
                        "tg_home": "home_team_total_goals",
                        "tg_away": "away_team_total_goals",
                        "alternative_total_goals": "alternative_total_goals",
                        "1st_half_alternative_total_goals": "1st_half_alternative_total_goals",
                        "2nd_half_alternative_total_goals": "2nd_half_alternative_total_goals",
                        
                        # Odd/Even
                        "odd_even": "goals_odd_even",
                        "odd_even_1t": "1st_half_goals_odd_even",
                        "odd_even_2t": "2nd_half_goals_odd_even",
                        "team_goals_odd_even": "team_goals_odd_even",
                        
                        # Correct Score
                        "cs": "correct_score",
                        "cs_1t": "1st_half_correct_score",
                        "cs_2t": "2nd_half_correct_score",
                        "cs_ht_ft": "half_time_full_time_correct_score",
                        
                        # Draw No Bet
                        "dnb": "draw_no_bet",
                        "dnb_1t": "1st_half_draw_no_bet",
                        "dnb_2t": "2nd_half_draw_no_bet",
                        
                        # Handicap
                        "handicap": "handicap_result",
                        "handicap_1t": "1st_half_handicap_result",
                        "handicap_2t": "2nd_half_handicap_result",
                        "asian_handicap": "asian_handicap",
                        
                        # Handicap No Bet
                        "hnb": "handicap_no_bet",
                        "hnb_1t": "1st_half_handicap_no_bet",
                        "hnb_2t": "2nd_half_handicap_no_bet",
                        
                        # Asian No Bet
                        "anb": "asian_no_bet",
                        "anb_1t": "1st_half_asian_no_bet",
                        "anb_2t": "2nd_half_asian_no_bet",
                        
                        # Goal No Bet
                        "gnb": "goal_no_bet",
                        
                        # Half More Goals
                        "half_more_goals": "half_more_goals",
                        
                        # Combo Markets
                        "comboDc1tOu": "combo_double_chance_1t_over_under",
                        "comboDc2tOu": "combo_double_chance_2t_over_under",
                        "combo_dc_multi": "combo_double_chance_multi",
                        
                        # Multi Goals
                        "multigol": "multi_goals",
                        "multi1t": "multi_goals_1t",
                        "multi2t": "multi_goals_2t",
                        "multi1t_ft": "multi_goals_1t_full_time",
                        "match_goals_range": "match_goals_range",
                        "1st_half_match_goals_range": "1st_half_match_goals_range",
                        "2nd_half_match_goals_range": "2nd_half_match_goals_range",
                        "home_team_match_goals_range": "home_team_match_goals_range",
                        "away_team_match_goals_range": "away_team_match_goals_range",
                        "match_goals_range_corners": "match_goals_range_corners",
                        "1st_half_2nd_half_match_goals_range": "1st_half_2nd_half_match_goals_range",
                        
                        # Special Markets
                        "home_score_1_2": "home_score_1_2",
                        "away_score_1_2": "away_score_1_2",
                        "home_wins_both": "home_wins_both_halves",
                        "away_wins_both": "away_wins_both_halves",
                        "home_or_away_win_both": "home_or_away_win_both_halves",
                        "home_win_at_least_one": "home_win_at_least_one_half",
                        "away_win_at_least_one": "away_win_at_least_one_half",
                        "wins_from_behind": "wins_from_behind",
                        "combo_1x2_first_goal": "combo_1x2_first_goal"
                    }
                    
                    # Aggiungi tutte le quote calcolate (con mappatura se disponibile)
                    for calc_key, calc_value in calculated_odds.items():
                        if isinstance(calc_value, list):
                            # Usa la mappatura se disponibile, altrimenti usa la chiave originale
                            quote_key = calculated_mapping.get(calc_key, calc_key)
                            evento_convertito["quote"][quote_key] = calc_value
                            
                            # Se è 1x2_1t o 1x2_2t, aggiorna anche quote_1x2 se necessario
                            if calc_key == "1x2_1t" and not evento_convertito["quote_1x2"]["1"]:
                                for item in calc_value:
                                    if isinstance(item, dict):
                                        header = (item.get("header") or "").strip()
                                        odds = item.get("odds")
                                        if header == "1":
                                            evento_convertito["quote_1x2"]["1"] = odds
                                        elif header == "X":
                                            evento_convertito["quote_1x2"]["X"] = odds
                                        elif header == "2":
                                            evento_convertito["quote_1x2"]["2"] = odds
            except Exception as calc_error:
                # Ignora errori nella lettura delle quote calcolate
                pass
            
            if "_id" in ev:
                evento_convertito["_id"] = str(ev["_id"])
            
            eventi.append(evento_convertito)
        
        return jsonify({
            "success": True,
            "results": eventi,
            "count": len(eventi)
        })
    except Exception as e:
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