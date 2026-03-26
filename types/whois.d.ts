declare module 'whois' {
  function lookup(
    domain: string,
    callback: (err: Error | null, data: string) => void
  ): void;
  function lookup(
    domain: string,
    options: Record<string, unknown>,
    callback: (err: Error | null, data: string) => void
  ): void;
}
