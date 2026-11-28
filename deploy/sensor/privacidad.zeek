# Scripts de la politica local de la imagen que no se cargan en el sensor.
# start-zeek.sh carga este archivo antes de "local": @unload hace que Zeek omita
# la carga posterior del script indicado (ver loaded_scripts.log).

# detect-MHR envia el SHA1 (no el archivo) de cada ejecutable, PDF, CAB, JAR, MP4
# o Flash que Zeek ve en claro, como consulta DNS TXT a <sha1>.malware.hash.cymru.com
# (ver match_file_types en detect-MHR.zeek). La consulta llega a Team Cymru desde el
# resolvedor de la organizacion y pasa en claro por los resolvedores intermedios.
# Para un archivo publico, el hash basta para saber que alguien de la organizacion
# lo obtuvo y cuando. Los hashes se siguen calculando y quedan en files.log
# (hash-all-files), sin salir del sensor.
@unload frameworks/files/detect-MHR
