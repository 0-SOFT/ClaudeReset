if __name__ == '__main__':
    import sys

    from claude_reset.network.protected_run import main
    raise SystemExit(main(sys.argv[1:]))
