// ye bas check karega user hai ya  nahi hain ham middleware bana raha h 

import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"

// yaha res ki jagah ( _ ) ye likha diya hu aise bhi chlta h
export const verifyJWT = asyncHandler(async(req,_,next)=>{
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","")
    
        if(!token){
            throw new ApiError(401,"Unauthorized request")
        }
    
        //jab token ho to ye verify karo 
        const decodedToken = jwt.verify(token,process.env.ACCESS_TOKEN_SECRET)
    
        //token ko id ke through search karo aur use do  
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")
        if(!user){
            throw new ApiError(401,"Invalid Access Token")
        }
        req.user = user;
        next()
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid access token")
    }
})