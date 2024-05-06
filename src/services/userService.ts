import bcrypt from 'bcryptjs';
import User, { IUser } from '../models/userModel';
import { Resend } from 'resend';
import jwt from 'jsonwebtoken';
import { createClient } from 'redis';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
// import { Socket } from 'socket.io';
import {Socket, Server as SocketIOServer } from 'socket.io';

type RedisClientType = ReturnType<typeof createClient>;




interface User {
    _id: {
      $oid: string;
    };
    name: string;
    username: string;
    password: string;
    email: string;
    activeSessions: any[];
    __v: number;
  }
  const resend = new Resend(process.env.RESEND_KEY as string);

  const client: RedisClientType = createClient({
    password: process.env.REDIS_PASSWORD,
    socket: {
        host: process.env.REDIS_HOST,
        port: Number(process.env.REDIS_PORT)
    }
});
client.connect()
  .then(() => console.log('Connected to Redis'))
  .catch((err: Error) => console.error('Could not connect to Redis', err));


export const login = async (req: Request, res: Response): Promise<Response> => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }
        console.log("username is valid  ");

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid password' });
        }
        console.log("password is valid  ");
        // Generate a 6-digit OTP
        const otp = crypto.randomInt(100000, 999999);

        try {
            // Store the OTP in Redis associated with the user's email, set to expire in 60 seconds
            const result = await client.set(`otp_${user.username}`, otp, {EX: 60});
            console.log('Result of storing OTP:', result);

             // Retrieve the OTP from Redis and log it
            const storedOtp = await client.get(`otp_${user.username}`);
            console.log(`Stored OTP for ${user.username}:`, storedOtp);
        } catch (err) {
            console.error('Error storing OTP:', err);
            return res.status(500).json({ message: 'An error occurred while storing the OTP.' });
        }

        try {
            // Send the OTP to the user's email
            await resend.emails.send({
                from: 'onboarding@resend.dev',
                to: user.email,
                subject: 'Your OTP for Our Service',
                html: `<p>Welcome to our service. We're glad to have you. Your OTP is <strong>${otp}</strong>. Please use this to complete your login.</p>`
            });
        } catch (err) {
            console.error('Error sending OTP:', err);
            return res.status(500).json({ message: 'An error occurred while sending the OTP.' });
        }

        return res.status(200).json({ message: 'Login successful. Please check your email for the OTP.' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'An error occurred during login.' });
    }
};

export const verifyOtp = async (req: Request, res: Response, io : SocketIOServer ): Promise<Response> => {
    try {
        const username = req.body.username;
        const otp = req.body.otp;
        const deviceType = req.body.deviceType;
        const browserName = req.body.browserName;

        // Check if all required data exists in the request
        if (!username || !otp || !deviceType || !browserName) {
            return res.status(400).json({ message: 'Missing required data in the request.' });
        }

        const timestamp = new Date().toISOString();
        const storedOtp = await client.get(`otp_${username}`);
        console.log({ storedOtp, otp ,username });
        if (!storedOtp || otp !== storedOtp) {
            console.log("Invalid OTP");
            return res.status(400).json({ message: 'Invalid OTP.' });
        }

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({ message: 'User not found!' });
        }

        // Create a token
        const token = jwt.sign({ id: user._id }, '6dcd4ce23d88e2ee95838f7b014b6284f4903928b8d98e6b3c4f8f1d8124ebfb358b35139c205e04c48416a15a4c9fdf9b60b3e8ad1a8a484b8636f92bbcb3a5', { expiresIn: '8h' });
        const newSession = {
            deviceType: deviceType,
            browserName: browserName,
            timestamp: timestamp,
            token: token,
            expiry: new Date(Date.now() + 8 * 60 * 60 * 1000) // Expires in 8 hours
        };
        
        // Add the new session to the user's activeSessions array
        await User.updateOne({ username }, { $push: { activeSessions: newSession } });
        
        console.log(newSession )
        
        // Store the username in Redis with an expiration date
        await client.set(`token_${token}`, username,{ EX: 60 * 60 * 8}); // Expires in 8 hours            
           
            return res.status(200).json({ user, token });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'An error occurred during OTP verification.' });
    }
};
export const logout = async (req: Request, res: Response, io : SocketIOServer): Promise<Response> => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided.' });
    }

    const username = await client.get(`token_${token}`);
    if (!username) {
        return res.status(401).json({ message: 'Invalid token.' });
    }

    const user = await User.findOne({ username });
    if (!user) {
        return res.status(404).json({ message: 'User not found.' });
    }

    // Remove the session from the user's activeSessions array
    const updatedSessions = user.activeSessions.filter((session: any) => session.token !== token);
    await User.updateOne({ username }, { activeSessions: updatedSessions });

    // Delete the token from Redis
    await client.del(`token_${token}`);

    return res.status(200).json({ message: 'Logged out successfully.' });

}
export const getSessionData = async (req: Request, res: Response , io : SocketIOServer): Promise<Response> => {
    const token = req.headers['authorization'] && req.headers['authorization'].split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'No token provided.' });
    }

    const username = await client.get(`token_${token}`);

    if (!username) {
        return res.status(401).json({ message: 'Invalid token.' });
    }

    io.on('connection', async (socket: Socket) => {
        socket.join(token);
        const user = await User.findOne({ username });

        if (user && user.activeSessions) {
            // Emit the active sessions
            io.to(token).emit('activeSession', user.activeSessions);
        }
    });

    return res.status(200).json({ message: 'Listening for active sessions.' });
}

export const register = async (userData: IUser): Promise<IUser> => {
    const { password, email } = userData;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ ...userData, password: hashedPassword });
    
    const savedUser = await user.save();

    // send welcome email
    await resend.emails.send({
        from: 'onboarding@resend.dev',
        to: email,
        subject: 'Welcome to Our Service',
        html: '<p>Welcome to our service. We\'re glad to have you.</p>'
    });

    return savedUser;
};

export const sendWelcomeEmail = async ({email, name}: {email: string, name: string}): Promise<void> => {
    // send a welcom email to the user
}

export const validateUsername = async (username: string): Promise<boolean> => {
    const user = await User.findOne({ username: username });
    return user ? true : false;
};

