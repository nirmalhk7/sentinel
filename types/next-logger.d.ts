declare module "next-logger" {
  const logger: {
    info: (message: string) => void;
    error: (message: string) => void;
    warn: (message: string) => void;
  };
  export default logger;
}
