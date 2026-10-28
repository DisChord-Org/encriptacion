import {
    CipherGCM, CipherGCMTypes, createCipheriv, createDecipheriv, createHash,
    createHmac, DecipherGCM, Hash, HashOptions, Hmac, randomBytes, randomInt,
    randomUUID, scryptSync, timingSafeEqual
} from 'node:crypto';
import { ResultadoCifrado, ResultadoClave } from './internal';

export function crearID(): string
{
    return randomUUID();
}

export function numeroAleatorio(minimo: number, maximo: number): number
{
    return randomInt(minimo, maximo);
}

export function textoAleatorio(longitud: number): Buffer
{
    return randomBytes(longitud);
}

export function crearHash(algoritmo: string = 'sha256', opciones?: HashOptions): Hash
{
    return createHash(algoritmo, opciones);
}

export function crearFirma(algoritmo: string = 'sha256', clave: string | Buffer): Hmac
{
    return createHmac(algoritmo, clave);
}

export function sonIguales(textoA: string | Buffer, textoB: string | Buffer): boolean
{
    const bufA: Buffer<ArrayBufferLike> = typeof textoA === 'string' ? Buffer.from(textoA) : textoA;
    const bufB: Buffer<ArrayBufferLike> = typeof textoB === 'string' ? Buffer.from(textoB) : textoB;

    if (bufA.length !== bufB.length)
    {
        return false;
    }

    return timingSafeEqual(bufA, bufB);
}

export function cifrar(texto: string, clave: string | Buffer, algoritmo: CipherGCMTypes = 'aes-256-gcm'): ResultadoCifrado
{
    const claveBuffer: Buffer<ArrayBufferLike> = typeof clave === 'string'
        ? (clave.length === 64 ? Buffer.from(clave, 'hex') : Buffer.from(clave.padEnd(32, '0').slice(0, 32)))
        : clave;

    const iv: Buffer = randomBytes(12);
    const cipher: CipherGCM = createCipheriv(algoritmo, claveBuffer, iv);

    const cifrado: Buffer<ArrayBuffer> = Buffer.concat([cipher.update(texto, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
        contenido: cifrado.toString('hex'),
        iv: iv.toString('hex'),
        tag: tag.toString('hex')
    };
}

export function descifrar(textoCifradoHex: string, clave: Buffer, ivHex: string, tagHex: string, algoritmo: CipherGCMTypes = 'aes-256-gcm'): string
{
    const decipher: DecipherGCM = createDecipheriv(algoritmo, clave, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

    const descifrado: Buffer<ArrayBuffer> = Buffer.concat([
        decipher.update(Buffer.from(textoCifradoHex, 'hex')),
        decipher.final()
    ]);

    return descifrado.toString('utf8');
}

export function encriptarClave(contrasena: string, sal: string | Buffer = randomBytes(16), longitudClave: number = 64): ResultadoClave
{
    const salBuffer: Buffer<ArrayBufferLike> = typeof sal === 'string' ? Buffer.from(sal, 'hex') : sal;
    const hash: Buffer = scryptSync(contrasena, salBuffer, longitudClave);

    return {
        hash: hash.toString('hex'),
        sal: salBuffer.toString('hex')
    };
}

export function verificarClave(contrasena: string, hashAlmacenadoHex: string, sal: string | Buffer, longitudClave: number = 64): boolean
{
    const salBuffer: Buffer<ArrayBufferLike> = typeof sal === 'string' ? Buffer.from(sal, 'hex') : sal;
    const hashActual: Buffer = scryptSync(contrasena, salBuffer, longitudClave);

    return sonIguales(hashActual, Buffer.from(hashAlmacenadoHex, 'hex'));
}
