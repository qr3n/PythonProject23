import asyncio
import ssl
import socket


async def scan_host(ip, port=443):
    try:
        # Попытка подключиться по TCP
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=1.5)

        print(f"Found: {ip}:{port} open")

        if port == 443:
            # Попытка вытащить SNI/Сертификат
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = writer.get_extra_info('socket')
            # Обертывание сокета в TLS для чтения инфо о сертификате
            sslsock = context.wrap_socket(sock, server_hostname=ip)
            cert = sslsock.getpeercert(binary_form=True)
            print(f"[{ip}] Получен SSL сертификат")

        writer.close()
        await writer.wait_closed()
    except:
        pass  # Порт закрыт или таймаут


# Пример запуска для перебора (для теста взят маленький кусочек)
async def main():
    tasks = [scan_host(f"158.160.1.{i}", 443) for i in range(1, 255)]
    await asyncio.gather(*tasks)


asyncio.run(main())