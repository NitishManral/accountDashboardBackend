import express from 'express';
import {Server as SocketIOServer } from 'socket.io';

import * as userController from '../controllers/userController';

export const userRoutes=(io: SocketIOServer ) =>{
    const router = express.Router();

    router.post('/register', userController.register);
    router.post('/login', userController.login);
    router.get('/validateusername/:username', userController.validateusername);
    router.post('/verifyOtp', (req,res)=>userController.verifyOtp(req,res,io));
    router.get('/getSession',(req,res)=> userController.getSessionData(req,res,io));
    router.get("/logout",(req,res)=> userController.logout(req,res,io));
    router.get("/", userController.home); // not allowed
    router.get("/hello", userController.homee); // allowed
    return router
};