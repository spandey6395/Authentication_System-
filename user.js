const express =require('express');
const db = require('./db');
const userRouter = express.Router();
 
const { hashSync, genSaltSync, compareSync } = require("bcrypt");
 
 
 
 
userRouter.param('userId', async (req, res, next, userId)=> {
    try{
        const user = await db.getOne("User", userId);
        req.user = user;
        next();
    } catch(e) {
        console.log(e);
        res.sendStatus(404);
    }
});
 
 
 
userRouter.get('/:userId',  (req, res, next)=>{
    res.status(200).json({user: req.user});
 
});
 
 
 
 
userRouter.post('/',  async (req, res, next)=>{
    try{
        const userName = req.body.user.userName;
        const email = req.body.user.email;
        let password = req.body.user.password;
 
 
              if (!userName || !email || !password) {
                return res.sendStatus(400);
             }
 
             const salt = genSaltSync(10);
             password = hashSync(password, salt);
 
              
 
        const user =  await db.insertUser(userName, email, password);
        res.json({user: user});
            
 
    } catch(e){    
        console.log(e);
        res.sendStatus(400);
    }
});
 
 
 
 
userRouter.put('/:id',  async (req, res, next)=>{
    try{
        const userName = req.body.user.userName;
        const role = req.body.user.role;
        const email = req.body.user.email;
        let password = req.body.user.password;
        const userId = req.params.id;
 
 
              if (!userName || !role || !email || !password) {
                return res.sendStatus(400);
             }
 
             const salt = genSaltSync(10);
             password = hashSync(password, salt);
 
              
 
        const user =  await db.updateUser(userName, role, email, password, userId);
        res.json({message: "user updated" });
            
 
    } catch(e){    
        console.log(e);
        res.sendStatus(400);
    }
});
 
 
 
userRouter.delete('/:id',  async (req, res, next)=>{
    try{
        const userId = req.params.id
        const user =  await db.deleteUser(userId);
        return res.sendStatus(204);
     
    } catch(e){    
        console.log(e);
        res.sendStatus(400);
    }
});
 
 
 
userRouter.get('/', async (req, res, next)=>{
    try {
        const users = await db.allUser();
        res.json({users: users});
    } catch(e) {
        console.log(e);
    }
});
 
 
 
 
 
 
 
 
module.exports = userRouter;