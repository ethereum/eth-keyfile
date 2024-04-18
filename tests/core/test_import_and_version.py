def test_import_and_version():
    import eth_keyfile

    assert isinstance(eth_keyfile.__version__, str)
