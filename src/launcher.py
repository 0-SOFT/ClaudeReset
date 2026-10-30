if __name__ == '__main__':
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == '--native-worker':
        from claude_reset.reset.native_worker import main
        raise SystemExit(main(sys.argv[2]))
    if len(sys.argv) == 4 and sys.argv[1] == '--protected-pump':
        from claude_reset.network.protected_run import pump_main
        raise SystemExit(pump_main(sys.argv[2], sys.argv[3]))
    from claude_reset.cli import main
    raise SystemExit(main())
