#!/usr/bin/env python3
"""
Script per parsare indirizzi_quote.txt e generare mapping tra categorie e mercati
"""

import re
from collections import defaultdict

def parse_quotes_file(filename):
    """Parsa il file indirizzi_quote.txt e estrae tutte le quote organizzate per categoria"""
    quotes_by_category = defaultdict(list)
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Pattern per estrarre ogni blocco di quote
    pattern = r'ID: (\d+)\s+Categoria: ([^\n]+)\s+(?:Nome: ([^\n]+)\s+)?(?:Header: ([^\n]+)\s+)?(?:Handicap: ([^\n]+)\s+)?Quota: ([^\n]+)\s+Percorso: ([^\n]+)'
    
    matches = re.finditer(pattern, content)
    
    for match in matches:
        quote_id = match.group(1)
        categoria = match.group(2).strip()
        nome = match.group(3).strip() if match.group(3) else None
        header = match.group(4).strip() if match.group(4) else None
        handicap = match.group(5).strip() if match.group(5) else None
        quota = match.group(6).strip()
        percorso = match.group(7).strip()
        
        quote_info = {
            'id': quote_id,
            'nome': nome,
            'header': header,
            'handicap': handicap,
            'quota': quota,
            'percorso': percorso
        }
        
        quotes_by_category[categoria].append(quote_info)
    
    return quotes_by_category

def map_category_to_market(categoria):
    """Mappa una categoria del file ai mercati nelle tab"""
    categoria_lower = categoria.lower()
    
    # Mapping principale - ordine importante (più specifici prima)
    mapping = {
        # Over/Under
        'goals over/under': 'Over/Under',
        'alternative goal line': 'O/U C/O',
        '1st half goal line': 'O/U 1T',
        'alternative 1st half goal line': 'O/U 1T C/O',
        
        # Handicap
        'asian handicap': 'Handicap',
        'alternative asian handicap': 'Handicap',
        '1st half asian handicap': 'Handicap 1T',
        'alternative 1st half asian handicap': 'Handicap 1T',
        'handicap 1t': 'Handicap 1T',
        'handicap 2t': 'Handicap 2T',
        'handicap result': 'Handicap',
        
        # GG/NG
        'gg': 'Gol Totali',
        'ng': 'Gol Totali',
        'gg 1t': 'GG/NG 1T',
        'ng 1t': 'GG/NG 1T',
        'gg 2t': 'GG/NG 2T',
        'ng 2t': 'GG/NG 2T',
        'gg + over': 'GG Special',
        'ng + over': 'GG Special',
        'gg + under': 'GG Special',
        'ng + under': 'GG Special',
        
        # Multi Goal
        'multi goal': 'Multi Gol',
        'multi goal 1t': 'Multi Gol 1T',
        'multi goal 2t': 'Multi Gol 2T',
        
        # Risultati Esatti
        'ris.esatto': 'Ris. Esatto',
        'ris.esatto 1t': 'Ris. Es. 1T',
        'goal esatti': 'Gol Esatti',
        'goal esatti 1t': 'GolTot 1T',
        'exact total goals': 'Gol Esatti',
        'exact 2nd half goals': 'GolTot 2T',
        
        # Combo
        'combo 1 + over': 'Combo',
        'combo 2 + over': 'Combo',
        'combo x + over': 'Combo',
        'combo 1 + under': 'Combo',
        'combo 2 + under': 'Combo',
        'combo x + under': 'Combo',
        'combo 1 + gg': 'Combo',
        'combo 2 + gg': 'Combo',
        'combo x + gg': 'Combo',
        'combo 1 + ng': 'Combo',
        'combo 2 + ng': 'Combo',
        'combo x + ng': 'Combo',
        
        # Tempo
        '1x2 1-10 min': '1X2 5 min',
        '1x2 2t': '2T',
        'finale 1x2': 'Parz./Fin.',
        'parziale/finale': 'Parz./Fin.',
        
        # Pari/Dispari
        'pari/dispari': 'Pari/Dispari',
        'pari/dispari 1t': 'Pari/Dis. 1T',
        '2nd half goals odd/even': 'Pari/Dis. 2T',
        'home team odd/even goals': 'P./D. Squadre',
        'away team odd/even goals': 'P./D. Squadre',
        
        # Gol Totali
        'casa u/o': 'GolTot Casa',
        'ospite u/o': 'GolTot Ospite',
        'u/o 2t': 'O/U 2T',
        'first half goals': 'GolTot 1T',
        
        # DNB
        'dnb': 'DNB',
        
        # Primo/Ultimo Gol
        'first team to score': 'Primo Gol',
        'last team to score': 'Ultimo Gol',
        'first goal method': 'Metodo 1° gol',
        'time of first goal brackets': 'Primo Gol Min',
        'time of 1st team goal': 'Primo Gol Min',
        'early goal': 'Goal (0 - 15)',
        'late goal': 'Goal (0 - 30)',
        
        # Altri
        'segna': 'Segna 1T 2T',
        'winning margin': 'Vince a 0',
        'half with most goals': 'Vince 1T o 2T',
        'number of goals in match': 'Gol Esatti',
    }
    
    # Cerca match esatto
    if categoria_lower in mapping:
        return mapping[categoria_lower]
    
    # Cerca match parziale (per categorie che contengono la chiave)
    for key, value in mapping.items():
        if key in categoria_lower:
            return value
    
    return None

def generate_columns_for_market(quotes_by_category, market_name):
    """Genera le colonne per un mercato specifico basandosi sulle quote disponibili"""
    columns = []
    
    # Trova tutte le categorie che mappano a questo mercato
    relevant_categories = []
    for categoria, quotes in quotes_by_category.items():
        mapped_market = map_category_to_market(categoria)
        if mapped_market == market_name:
            relevant_categories.append((categoria, quotes))
    
    if not relevant_categories:
        return None
    
    # Genera colonne in base al tipo di mercato
    if market_name == 'Over/Under':
        # Raccogli tutti i valori Over/Under unici
        o_u_values = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                if quote['nome']:
                    o_u_values.add(f"Over {quote['nome']}")
                    o_u_values.add(f"Under {quote['nome']}")
        columns = sorted(list(o_u_values))
    
    elif market_name == 'Handicap':
        # Raccogli tutti gli handicap unici
        handicap_values = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                if quote['handicap']:
                    handicap_values.add(f"H{quote['header']} ({quote['handicap']})")
        columns = sorted(list(handicap_values))
    
    elif market_name == 'Gol Totali':
        columns = ['GG', 'NG']
    
    elif market_name == 'GG/NG 1T':
        columns = ['GG 1T', 'NG 1T']
    
    elif market_name == 'GG/NG 2T':
        columns = ['GG 2T', 'NG 2T']
    
    elif market_name == 'Multi Gol':
        # Raccogli tutti i range di gol
        ranges = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                if quote['nome']:
                    ranges.add(quote['nome'])
        columns = sorted(list(ranges))
    
    elif market_name == 'Multi Gol 1T':
        ranges = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                if quote['nome']:
                    ranges.add(quote['nome'])
        columns = sorted(list(ranges))
    
    elif market_name == 'Multi Gol 2T':
        ranges = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                if quote['nome']:
                    ranges.add(quote['nome'])
        columns = sorted(list(ranges))
    
    elif market_name == 'Combo':
        # Raccogli tutte le combo
        combos = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                combo_label = f"{quote['nome']} + {quote['header']} {quote['handicap']}"
                combos.add(combo_label)
        columns = sorted(list(combos))
    
    elif market_name == 'GG Special':
        combos = set()
        for categoria, quotes in relevant_categories:
            for quote in quotes:
                if quote['nome']:
                    combos.add(quote['nome'])
        columns = sorted(list(combos))
    
    return columns

def main():
    quotes_by_category = parse_quotes_file('indirizzi_quote.txt')
    
    # Stampa statistiche
    print(f"Totale categorie trovate: {len(quotes_by_category)}")
    print("\nCategorie trovate:")
    for categoria in sorted(quotes_by_category.keys()):
        print(f"  - {categoria}: {len(quotes_by_category[categoria])} quote")
    
    # Genera mapping per ogni mercato
    print("\n\nMapping categorie -> mercati:")
    market_mapping = defaultdict(list)
    for categoria in quotes_by_category.keys():
        market = map_category_to_market(categoria)
        if market:
            market_mapping[market].append(categoria)
        else:
            print(f"  ⚠️  Categoria non mappata: {categoria}")
    
    print("\n\nMercati con categorie mappate:")
    for market, categories in sorted(market_mapping.items()):
        print(f"\n{market}:")
        for cat in categories:
            print(f"  - {cat}")
    
    # Genera colonne per ogni mercato
    print("\n\nColonne generate per mercato:")
    markets = ['Over/Under', 'Handicap', 'Gol Totali', 'GG/NG 1T', 'GG/NG 2T', 
               'Multi Gol', 'Multi Gol 1T', 'Multi Gol 2T', 'Combo', 'GG Special']
    
    for market in markets:
        columns = generate_columns_for_market(quotes_by_category, market)
        if columns:
            print(f"\n{market}: {columns}")

if __name__ == '__main__':
    main()

