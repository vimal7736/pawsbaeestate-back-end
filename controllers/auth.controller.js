import bcrypt from "bcrypt"
import prisma from "../lib/prisma.js"
import jwt from "jsonwebtoken"

export const register = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        if (!username ) {
            return res.status(400).json({ message: 'Please provide username' });
        } else if(!email){
            return res.status(400).json({ message: 'Please provide email' });
        } else if(!password){
            return res.status(400).json({ message: 'Please provide password' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await prisma.user.create({
            data: {
                username,
                email,
                password: hashedPassword,
            },
        });
        res.status(201).json({ message: 'User registered successfully', newUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to create User again' });
    }
};
export const login = async (req, res)=>{
 const { username,password} = req.body;

 try {
    const user = await prisma.user.findUnique({
        where:{username}
    })
    
  if (!user) return res.status(401).json({message:"Invalid Credentials!"});

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if(!isPasswordValid) return res.status(401).json({message:"Invalid Credentials!"})


    // res.setHeader("Set-Cookie", "test=" + "myValue").json("success");

    const age = 1000*60*60*24*2;

    const token = jwt.sign(
    {
        id:user.id,
        isAdmin:false,
    },
    process.env.JWT_SECRET_KET, {expiresIn:age});

    const { password: userPassword, ...userInfo} = user
    res.cookie("token", token,{
        httpOnly: true,
        // secure:true,
        maxAge:  age
    })
    .status(200)
    .json(userInfo);
    
 } catch (error) {
    console.error(error);
    res.status(500).json({message: 'Failed to login'})
    
 }
 //check user exist
 //check password is correcr 
 // generte cookoe token and send to user
}
export const logout = (req, res)=>{
res.clearCookie("token").status(200).json({message:"Logout Successfully"});
}