import socket

from cloudsentry import probe


def listening_socket():
    server = socket.create_server(("127.0.0.1", 0))
    return server, server.getsockname()[1]


def test_open_and_closed_ports():
    server, port = listening_socket()
    with server:
        assert probe.tcp_open("127.0.0.1", port, timeout=1)
    assert not probe.tcp_open("127.0.0.1", port, timeout=1, tries=1)


def test_probe_returns_one_answer_per_target():
    server, port = listening_socket()
    with server:
        closed = listening_socket()
        closed[0].close()
        answers = probe.probe([("127.0.0.1", port), ("127.0.0.1", closed[1])])
    assert answers == {("127.0.0.1", port): True, ("127.0.0.1", closed[1]): False}
