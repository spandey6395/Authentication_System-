//apiRouter.js
 
 
const express =require('express');
const apiRouter = express.Router();
 
 const jsonwebtoken = require('jsonwebtoken');
const db = require('./db');
const { hashSync, genSaltSync, compareSync } = require("bcrypt");
const cookieParser = require('cookie-parser');
 
const userRouter = require('./user');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); 
 
apiRouter.use(cookieParser());
 
apiRouter.post('/register', async (req, res, next)=>{
    try{
        const userName = req.body.userName;
        const email = req.body.email;
        let password = req.body.password;
  
  
              if (!userName || !email || !password) {
                return res.sendStatus(400);
             }
  
             const salt = genSaltSync(10);
             password = hashSync(password, salt);
  
               
  
        const user =  await db.insertUser(userName, email, password);
         
        const jsontoken = jsonwebtoken.sign({user: user}, process.env.SECRET_KEY, { expiresIn: '30m'} );
        res.cookie('token', jsontoken, { httpOnly: true, secure: true, SameSite: 'strict' , expires: new Date(Number(new Date()) + 30*60*1000) }); //we add secure: true, when using https.
 
 
        res.json({token: jsontoken});
 
            //return res.redirect('/mainpage');
  
    } catch(e){    
        console.log(e);
        res.sendStatus(400);
    }
});
 
 
 
 
 apiRouter.post('/login', async(req, res, next)=>{
    try{
    const email = req.body.email;
    const password = req.body.password;
    user = await db.getUserByEmail(email);
     
    if(!user){
        return res.json({
            message: "Invalid email or password"
        })
    }
 
    const isValidPassword = compareSync(password, user.password);
    if(isValidPassword){
        user.password = undefined;
        const jsontoken = jsonwebtoken.sign({user: user}, process.env.SECRET_KEY, { expiresIn: '30m'} );
        res.cookie('token', jsontoken, { httpOnly: true, secure: true, SameSite: 'strict' , expires: new Date(Number(new Date()) + 30*60*1000) }); //we add secure: true, when using https.
 
        res.json({token: jsontoken});
       //return res.redirect('/mainpage') ;
 
    }  else{
        return res.json({
            message: "Invalid email or password"
        });
    } 
 
    } catch(e){
        console.log(e);
    }
});
 
 
 
 
 
 
 
 
    
  
//  Verify Token
async function  verifyToken  (req, res, next){
    
   const token=req.cookies.token;
    console.log(token);
     
    if(token === undefined  ){
         
            return res.json({
                message: "Access Denied! Unauthorized User"
              });
    } else{
 
        jsonwebtoken.verify(token, process.env.SECRET_KEY, (err, authData)=>{
            if(err){
                res.json({
                    message: "Invalid Token..."
                  });
 
            } else{
                
               console.log(authData.user.role);
               const role = authData.user.role;
               if(role === "admin"){
 
                next();
               } else{
                   return res.json({
                       message: "Access Denied! you are not an Admin"
                     });
 
               }
            }
        })
    } 
}
 
 
apiRouter.use('/user', verifyToken, userRouter);

apiRouter.post('/forgotPassword', async(req, res, next)=>{
    try{
    const email = req.body.email;
    console.log(email);
     
    const origin = req.header('Origin'); // we are  getting the request origin from  the HOST header
     
    const user = await db.getUserByEmail(email);
     
     
    if(!user){
        // here we always return ok response to prevent email enumeration
       return res.json({status: 'ok'});
    }
    // Get all the tokens that were previously set for this user and set used to 1. This will prevent old and expired tokens  from being used. 
    await db.expireOldTokens(email, 1);

    // create reset token that expires after 1 hours
   const resetToken = crypto.randomBytes(40).toString('hex');
   const resetTokenExpires = new Date(Date.now() + 60*60*1000);
   const createdAt = new Date(Date.now());
    
    
   const expiredAt = resetTokenExpires;
   
    

   //insert the new token into resetPasswordToken table
   await db.insertResetToken(email, resetToken,createdAt, expiredAt, 0);

   // send email
   await sendPasswordResetEmail(email,resetToken, origin);
   res.json({ message: 'Please check your email for a new password' });
     

    } catch(e){
        console.log(e);
    }
});
 
 
 

async function sendEmail({ to, subject, html, from = process.env.EMAIL_FROM }) {
   
    
   const transporter = nodemailer.createTransport({
           host: 'smtp.mandrillapp.com',
           port: 587,
           auth: {
             user: process.env.USER, // generated mandrillapp user
             pass: process.env.PASS // generated mandrillapp password
           }
   })
       
  
  await transporter.sendMail({ from, to, subject, html });

   console.log("email sent sucessfully");
       
   };


    


async function sendPasswordResetEmail(email, resetToken, origin) {
       let message;
        
       if (origin) {
           const resetUrl = `${origin}/apiRouter/resetPassword?token=${resetToken} email=${email}`;
           message = `<p>Please click the below link to reset your password, the link will be valid for 1 hour:</p>
                      <p><a href="${resetUrl}">${resetUrl}</a></p>`;
       } else {
           message = `<p>Please use the below token to reset your password with the <code>/apiRouter/reset-password</code> api route:</p>
                      <p><code>${resetToken}</code></p>`;
       }
    
       await sendEmail({
           from: process.env.EMAIL_FROM,
           to: email,
           subject: ' Reset your Password',
           html: `<h4>Reset Password </h4>
                  ${message}`
       });
   }




//  Reset token validate
async function  validateResetToken  (req, res, next){

   const email = req.body.email;
   const resetToken = req.body.token;
    
    
   
   if (!resetToken || !email) {
       return res.sendStatus(400);
      }

   // then we need to verify if the token exist in the resetPasswordToken and not expired.
   const currentTime =  new Date(Date.now());
    
   const token = await db.findValidToken(resetToken, email, currentTime);
   
    
   if (!token) { 
     res.json ( 'Invalid token, please try again.');
   }

   next();
   };

   
   
   
   
   
   apiRouter.post('/resetPassword', validateResetToken, async(req, res, next)=>{
       try{
           
           const newPassword = req.body.password;
           const email = req.body.email;
           

           if  (!newPassword) {
             return res.sendStatus(400);
            }
        

          const user = await db.getUserByEmail(email);

           
          const salt = genSaltSync(10);
          const  password = hashSync(newPassword, salt);
           
          await db.updateUserPassword(password, user.id);
           
          res.json({ message: 'Password reset successful, you can now login with the new password' });

       } catch(e){
           console.log(e);
       }
      })
 
 
    
module.exports = apiRouter;