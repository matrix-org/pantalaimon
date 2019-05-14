import pdb

from conftest import faker


class TestClass(object):
    def test_account_loading(self, panstore):
        accounts = panstore.load_all_users()
        # pdb.set_trace()
        assert len(accounts) == 10

    def test_token_saving(self, panstore, access_token):
        accounts = panstore.load_all_users()
        user_id = accounts[0][0]
        device_id = accounts[0][1]

        panstore.save_access_token(user_id, device_id, access_token)

        token = panstore.load_access_token(user_id, device_id)
        access_token == token

    def test_child_clinets_storing(self, panstore, client):
        server = faker.hostname()
        clients = panstore.load_clients(server)
        assert not clients

        panstore.save_client(server, client)

        clients = panstore.load_clients(server)
        assert clients

        client2 = faker.client()
        panstore.save_client(server, client2)
        clients = panstore.load_clients(server)
        assert len(clients) == 2

    def test_server_account_storing(self, panstore):
        accounts = panstore.load_all_users()

        user_id, device_id = accounts[0]
        server = faker.hostname()

        panstore.save_server_user(server, user_id)

        server2 = faker.hostname()
        user_id2, device_id2 = accounts[1]
        panstore.save_server_user(server2, user_id2)

        server_users = panstore.load_users(server)
        assert (user_id, device_id) in server_users
        assert (user_id2, device_id2) not in server_users
