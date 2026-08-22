// ============================================================
// Fix para route_probe.js — PS4 WebKit 605.1.15
// 
// PS4 WebKit no soporta String.prototype.padStart (ES2017)
// Este polyfill lo añade para que route_probe funcione
//
// INSTRUCCIONES:
// Añadir al INICIO de route_probe.js, antes de cualquier código
// ============================================================

// Polyfill padStart para PS4 WebKit
if (!String.prototype.padStart) {
    String.prototype.padStart = function(targetLength, padString) {
        targetLength = targetLength >> 0;
        padString = String(typeof padString !== 'undefined' ? padString : ' ');
        if (this.length >= targetLength) {
            return String(this);
        }
        targetLength = targetLength - this.length;
        if (targetLength > padString.length) {
            padString += padString.repeat(targetLength / padString.length);
        }
        return padString.slice(0, targetLength) + String(this);
    };
}

// Polyfill repeat (también falta en WebKit viejo)
if (!String.prototype.repeat) {
    String.prototype.repeat = function(count) {
        var str = '' + this;
        count = +count;
        var result = '';
        while (count > 0) {
            if (count % 2 === 1) result += str;
            if (count > 1) str += str;
            count >>= 1;
        }
        return result;
    };
}

// ============================================================
// Alternativa: si no quieres polyfill, reemplaza TODAS las
// ocurrencias de:
//
//   .toString(16).padStart(2, '0')
//
// con:
//
//   .toString(16).length < 2 ? '0' + .toString(16) : .toString(16)
//
// O mejor, usa esta función helper:
// ============================================================

function hex8(val) {
    var s = (val & 0xFF).toString(16);
    return s.length < 2 ? '0' + s : s;
}

function hex16(val) {
    var s = (val & 0xFFFF).toString(16);
    while (s.length < 4) s = '0' + s;
    return s;
}

function hex32(val) {
    var s = (val >>> 0).toString(16);
    while (s.length < 8) s = '0' + s;
    return s;
}

// ============================================================
// TAMBIÉN: Modificar hexdump() para dumpear TODOS los bytes
// 
// La v5 solo dumpea los primeros 96 bytes del header.
// Cambiar el límite para dumpear la respuesta COMPLETA:
//
// ANTES:
//   for (var b = 0; b < 96; b += 16)
//
// DESPUÉS:
//   for (var b = 0; b < totalBytes; b += 16)
//
// Donde totalBytes = el valor de rtm_msglen del header
// (bytes 0-1 del mensaje, little-endian)
//
// Esto dumpeará los 1682 bytes completos de H1
// ============================================================
