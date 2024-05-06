// userModel.js
const mongoose = require('mongoose');

export interface activeSessions {
    token: string;
    expiry: Date;
    timestamp: Date;
    browserName: string;
    deviceType: string;
}

export interface IUser {
    name: string;
    username: string;
    password: string;
    email: string;
    activeSessions: activeSessions[];
  }
const UserSchema = new mongoose.Schema({
    name: String,
    username: String,
    password: String,
    email: String,
    activeSessions: [{
        token: String,
        expiry: Date,
        timestamp: Date,
        browserName: String,
        deviceType: String
    }]
});

const User = mongoose.model('User', UserSchema);

export default User;