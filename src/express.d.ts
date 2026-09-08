declare global {
  namespace Express {
    interface Request {
      tokenUserId?: string;
    }
  }
}

export {};
