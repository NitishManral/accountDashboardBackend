import { Request, Response } from 'express';
import * as userService from '../services/userService';
import {Socket, Server as SocketIOServer } from 'socket.io';
import exp from 'constants';


export const register = async (req: Request, res: Response): Promise<void> => {
    try {
        const user = await userService.register(req.body);
        res.status(201).json({ message: 'User registered', user });
    } catch (error : any) {
        res.status(500).json({ message: error.message });
    }
};

export const verifyOtp = async (req: Request, res: Response, io: SocketIOServer): Promise<void> => {
    try {
        await userService.verifyOtp(req, res, io);
    } catch (error : any) {
        console.error(error);
        res.status(500).json({ message: 'An error occurred during OTP verification.' });
    }
};

export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        await userService.login(req, res);
    } catch (error: any) {
        res.status(500).json({ message: error.message });
    }
};
export const getSessionData = async (req: Request, res: Response , io : SocketIOServer): Promise<void> => {
    try {
        await userService.getSessionData(req, res, io);
    } catch (error : any) {
        res.status(500).json({ message: error.message });
    }

}

export const logout = async (req: Request, res: Response, io : SocketIOServer): Promise<void> => {
    try {
        await userService.logout(req, res,io);
    } catch (error : any) {
        res.status(500).json({ message: error.message });
    }
}
export const validateusername = async (req: Request, res: Response): Promise<void> => {
    const username = req.params.username;
    console.log(username );
    try {
        const exists = await userService.validateUsername(username);
        res.json({ exists: exists });
    } catch (err : any) {
        res.status(500).json({ error: err.message });
    }
};

export const home = async (req: Request, res: Response): Promise<void> => {
    res.status(200).json({message:"Welcome to the home page"});
}

export const homee = async (req: Request, res: Response): Promise<void> => {
    res.status(200).json({message:"sadfasf Welcome to the homee page"});
}
