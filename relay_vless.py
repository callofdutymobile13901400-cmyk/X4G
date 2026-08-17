# relay_vless.py
# VLESS Relay — بدون circular import

import asyncio
import secrets
from datetime import datetime

from fastapi import WebSocket, WebSocketDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    is_link_allowed,
    is_ip_allowed,
    save_state,
    log_activity,
    now_ir,
)

from state import (
    RELAY_BUF,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
)

from speed_limit import throttle


def _ws_client_ip(ws: WebSocket) -> str:
    fwd = ws.headers.get("x-forwarded-for")

    if fwd:
        return fwd.split(",")[0].strip()

    real_ip = ws.headers.get("x-real-ip")

    if real_ip:
        return real_ip.strip()

    return ws.client.host if ws.client else "unknown"


async def parse_vless_header(chunk: bytes):

    if len(chunk) < 24:
        raise ValueError("chunk too small")

    pos = 1

    pos += 16

    addon_len = chunk[pos]
    pos += 1 + addon_len

    command = chunk[pos]
    pos += 1

    port = int.from_bytes(
        chunk[pos:pos+2],
        "big"
    )

    pos += 2

    addr_type = chunk[pos]
    pos += 1


    if addr_type == 1:

        address = ".".join(
            str(b)
            for b in chunk[pos:pos+4]
        )

        pos += 4


    elif addr_type == 2:

        dlen = chunk[pos]
        pos += 1

        address = chunk[
            pos:pos+dlen
        ].decode(
            "utf-8",
            errors="ignore"
        )

        pos += dlen


    elif addr_type == 3:

        ab = chunk[pos:pos+16]

        address = ":".join(
            f"{ab[i]:02x}{ab[i+1]:02x}"
            for i in range(0,16,2)
        )

        pos += 16


    else:
        raise ValueError(
            f"unknown addr type {addr_type}"
        )


    return command, address, port, chunk[pos:]



async def check_and_use(uid: str, n: int):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if link is None:
            return False


        if not is_link_allowed(link):
            return False


        link["used_bytes"] += n


        stats["total_bytes"] += n


        hourly_traffic[
            now_ir().strftime("%H:00")
        ] += n


    return True



async def relay_ws_to_tcp(
    ws,
    writer,
    conn_id,
    uid
):

    try:

        while True:

            msg = await ws.receive()


            if msg["type"] == "websocket.disconnect":
                break


            data = (
                msg.get("bytes")
                or
                (msg.get("text") or "").encode()
            )


            if not data:
                continue


            if not await check_and_use(
                uid,
                len(data)
            ):

                await ws.close(
                    code=1008,
                    reason="quota"
                )

                break


            await throttle(
                uid,
                len(data)
            )


            stats["total_requests"] += 1


            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)


            writer.write(data)


            if writer.transport.get_write_buffer_size() > RELAY_BUF:

                await writer.drain()


    except Exception:
        pass


    finally:

        try:
            writer.write_eof()

        except Exception:
            pass




async def relay_tcp_to_ws(
    ws,
    reader,
    conn_id,
    uid
):

    first = True


    try:

        while True:

            data = await reader.read(
                RELAY_BUF
            )


            if not data:
                break


            if not await check_and_use(
                uid,
                len(data)
            ):

                await ws.close(
                    code=1008,
                    reason="quota"
                )

                break


            await throttle(
                uid,
                len(data)
            )


            if conn_id in connections:
                connections[conn_id]["bytes"] += len(data)


            payload = (
                b"\x00\x00" + data
                if first
                else data
            )


            first = False


            await ws.send_bytes(
                payload
            )


    except Exception:
        pass




async def websocket_tunnel(
    ws: WebSocket,
    uuid: str
):

    await ws.accept()


    async with LINKS_LOCK:

        link = LINKS.get(uuid)


    if not is_link_allowed(link):

        await ws.close(
            code=1008,
            reason="not authorized"
        )

        return



    ip = _ws_client_ip(ws)


    if not is_ip_allowed(
        link,
        uuid,
        ip
    ):

        await ws.close(
            code=1008,
            reason="ip limit"
        )

        return



    conn_id = secrets.token_urlsafe(6)


    connections[conn_id] = {

        "uuid": uuid,

        "ip": ip,

        "transport": "vless-ws",

        "connected_at":
            datetime.now().isoformat(),

        "bytes": 0,

    }



    writer = None


    try:

        first_msg = await asyncio.wait_for(
            ws.receive(),
            timeout=15
        )


        first_chunk = (
            first_msg.get("bytes")
            or
            (first_msg.get("text") or "").encode()
        )


        command,address,port,payload = await parse_vless_header(
            first_chunk
        )


        reader,writer = await asyncio.wait_for(
            asyncio.open_connection(
                address,
                port
            ),
            timeout=10
        )


        if payload:

            writer.write(payload)

            await writer.drain()



        await asyncio.wait(
            [
                asyncio.create_task(
                    relay_ws_to_tcp(
                        ws,
                        writer,
                        conn_id,
                        uuid
                    )
                ),

                asyncio.create_task(
                    relay_tcp_to_ws(
                        ws,
                        reader,
                        conn_id,
                        uuid
                    )
                )
            ],

            return_when=asyncio.FIRST_COMPLETED
        )


        asyncio.create_task(
            save_state()
        )


    except WebSocketDisconnect:
        pass


    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append({

            "error": str(exc),

            "time":
            datetime.now().isoformat()

        })


        logger.error(
            f"WS error {exc}"
        )


    finally:


        if writer:

            try:

                writer.close()

                await writer.wait_closed()

            except Exception:

                pass


        connections.pop(
            conn_id,
            None
        )
