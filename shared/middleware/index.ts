import { Request, Response, NextFunction } from "express";
import { JWTPayload, logError, ServiceError } from "../types";
import { createErrorResponse } from "../utils";
import jwt from "jsonwebtoken";

// Extends express request interface to include custom properties
declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

export function authenticateToken() {};

export function asyncHandler() {};

export function validateRequest() {};

export function errorHandler(error: ServiceError, req: Request, res: Response, next: NextFunction) {
    logError(error, {
        method: req.method,
        url: req.url,
        body: req.body,
        params: req.params,
        query: req.query
    });

    const statusCode = error.statusCode || 500;
    const message = error.message || "Internal Server Error";

    res.status(statusCode).json(createErrorResponse(message));
};

export function corsOptions() {
    return {
        origin: process.env.CORS_ORIGIN || "http://localhost:3000",
        credentials: process.env.CORS_CREDENTIALS === "true",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"]
    }
};

export function healthCheck(req: Request, res: Response) {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
};