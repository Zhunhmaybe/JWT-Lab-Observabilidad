# Guía de Penetración: Explotación de JWT (Payload Tampering)

Este laboratorio simula una aplicación web real. El objetivo es elevar nuestros privilegios de `user` a `admin` manipulando la sesión del navegador, sin tener acceso a la terminal del servidor.

## Fase 1: Reconocimiento y Extracción
1. Ingresa a la aplicación vulnerable desde tu navegador: `https://<IP_DEL_SERVIDOR>/dashboard`
2. Inicia sesión como un usuario normal:
   * **Usuario:** `alumno1`
   * **Contraseña:** `1234`
3. Una vez dentro, la aplicación generará tu token JWT de sesión. Puedes extraerlo de dos formas:
   * **Visual:** Cópialo directamente del cuadro de texto "Tu Token JWT actual".
   * **Hacker (F12):** Abre las herramientas de desarrollador de tu navegador, ve a la pestaña **Application** (o Almacenamiento), busca **Local Storage** y copia el valor de `jwt_token`.

## Fase 2: Manipulación (Tampering)
1. Abre una nueva pestaña y dirígete a [jwt.io](https://jwt.io).
2. Pega tu token en la sección "Encoded".
3. A la derecha, en la sección **PAYLOAD**, busca la línea que dice `"role": "user"`.
4. Modifica esa línea para que diga `"role": "admin"`.
5. Copia el nuevo token resultante (notarás que la firma al final dice "Invalid Signature", esto es lo que queremos probar).

## Fase 3: Explotación (Lanzando el ataque)
Para esta fase, usaremos **Postman** o la consola de terminal de **tu propia computadora** (usando `curl`).

**Ataque a la ruta protegida (Fallido):**
Lanza este comando reemplazando el token por el que falsificaste en jwt.io:
```bash
curl -sk -H "Authorization: Bearer <TU_TOKEN_FALSIFICADO>" https://<IP_DEL_SERVIDOR>/admin