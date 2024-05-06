import express, { Request, Response, NextFunction } from 'express';
import mongoose, { ConnectOptions } from 'mongoose';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import cors from 'cors';
import rateLimit, { Options } from 'express-rate-limit';
import {userRoutes} from './routes/userRoutes';
import jwt, { VerifyErrors } from 'jsonwebtoken';
import { Server as SocketIOServer, Socket } from 'socket.io';
import { createServer, Server as HTTPServer } from 'http';
import { createClient } from 'redis';
import { config } from 'dotenv';
import { Resend } from 'resend';
config();
type RedisClientType = ReturnType<typeof createClient>;

const { connect } = mongoose;
const { json } = bodyParser;
const { verify } = jwt;

const app = express();
const port = 3000;


mongoose.connect(process.env.MONGO_URI as string, {} as ConnectOptions)
    .then(() => console.log('MongoDB connected...'))
    .catch((err: Error) => console.log(err));

const client: RedisClientType = createClient({
    password: process.env.REDIS_PASSWORD,
    socket: {
        host: process.env.REDIS_HOST,
        port: Number(process.env.REDIS_PORT)
    }
});

const resend = new Resend(process.env.RESEND_KEY as string);
client.connect();
client.on('connect', () => {
    console.log('Redis connected...');
});
// Enable rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000 // limit each IP to 100 requests per windowMs
} as Options);


app.use(limiter);
app.use(morgan('dev')); // logging
app.use(json()); // parse json request body
app.use(cors()); // enable CORS

app.use(async (req: Request, res: Response, next: NextFunction) => {
    // Skip token authentication for /login and /register routes
    if (req.path === '/api/users/login' || req.path === '/api/users/register' || req.path === '/api/users/validateusername' || req.path === '/api/users/hello' ||req.path === '/api/users/verifyOtp' ) {
        return next();
    }

    // Extract token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.sendStatus(401); // Send 401 Unauthorized if no token is provided
    }
    // Check if the token exists in Redis
    const tokenExists = await client.exists(`token_${token}`);
    if (!tokenExists) {
        return res.sendStatus(401).json({message : "error "}); // Send 401 Unauthorized if the token does not exist in Redis
    }

    // Verify the token
    verify(token, '6dcd4ce23d88e2ee95838f7b014b6284f4903928b8d98e6b3c4f8f1d8124ebfb358b35139c205e04c48416a15a4c9fdf9b60b3e8ad1a8a484b8636f92bbcb3a5', (err: VerifyErrors | null) => {
        if (err) {
            return res.sendStatus(403).json({message : "error "}); // Send 403 Forbidden if token is not valid
        }
        next(); // Pass control to the next middleware function
    });
});

// Create an HTTP server and wrap the Express app
const httpServer: HTTPServer = createServer(app);

// Create a Socket.IO server and attach it to the HTTP server
const io: SocketIOServer = new SocketIOServer(httpServer, {
    cors: {
        origin: "*", // or wherever your client is hosted
        methods: ["GET", "POST"],
        allowedHeaders: ["my-custom-header"],
        credentials: true
    }
});
// Use the user routes
app.use('/api/users', userRoutes(io));


httpServer.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});