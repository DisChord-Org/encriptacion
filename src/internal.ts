export interface ResultadoClave
{
    hash: string;
    sal: string;
}

export interface ResultadoCifrado {
    contenido: string;
    iv: string;
    tag: string;
}