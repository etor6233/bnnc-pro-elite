use std::net::{TcpListener, TcpStream};
use std::thread;
use tungstenite::{Message, accept, client};

#[test]
fn selected_tungstenite_version_flushes_automatic_pong_with_identical_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut socket = accept(stream).unwrap();
        socket.send(Message::Ping(vec![1, 2, 3].into())).unwrap();
        let response = socket.read().unwrap();
        assert_eq!(response, Message::Pong(vec![1, 2, 3].into()));
        socket.send(Message::Text("done".into())).unwrap();
    });

    let stream = TcpStream::connect(address).unwrap();
    let (mut client, _) = client(format!("ws://{address}"), stream).unwrap();
    assert_eq!(client.read().unwrap(), Message::Ping(vec![1, 2, 3].into()));
    // This mirrors the production adapter: tungstenite already queued the
    // matching pong, so flush it rather than constructing a manual response.
    client.flush().unwrap();
    assert_eq!(client.read().unwrap(), Message::Text("done".into()));
    server.join().unwrap();
}
