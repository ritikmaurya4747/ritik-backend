import {asyncHandler} from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { response } from "express";

const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        //refreshToken ko database me save kar rahe hai login me use hoga 
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
        //jab ye sab successful  yaha tak ho jayega to inhe return kar do 
        return {accessToken,refreshToken}

    } catch (error) {
        throw new ApiError(500,'Something went wrong while generating refresh and access token')
    }
}

// Register user
const registerUser = asyncHandler( async(req,res) =>{
    // get user details from frontend  
    // validation - not empty   
    // check if user already exists: username , email
    // check for images, check for avatar
    // upload them to cloudinary , avatar
    // create user object -ceate entry in database
    // remove password and refresh token field from response
    // check for user creation 
    // returns response
    // 9:54:00 time important  SEE*************************************


    const {fullName, email, username, password} = req.body
    // console.log("email",email);

    if([fullName, email, username, password].
        some((field) => field?.trim() === "")){
            throw new ApiError(400, "All fields are required")
        }
    
    //agar user pahale se hi hain to 
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if(existedUser){
        throw new ApiError(409, "User email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length >0){
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required")
    }

    //upload on cloudinary files or images
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!avatar){
        throw new ApiError(400,"Avtar file is required")
    }

    //enter in database 
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"    //ye sab nahi chahiye 
    )
    if(!createdUser){
        throw new ApiError(500,"Something went worg while registering the user")
    }
    //agar user proper create ho gaya h to use as response bhej do
    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered successfuly")
    )
})

// Login user
const loginUser = asyncHandler(async(req,res) =>{
    // req body -> data
    // username or email
    // find the user
    // password checks 
    // access and refresh token
    // send cokkies  
    // video part two time(9:25)

    const {email, username, password} =req.body
    if(!(username || !email)){   //01:05:55
        throw new ApiError(400,"username or email is required")
    }

    // dono me se ek email or username  hona hi chahiye
    const user = await User.findOne({$or:[{username},{email}]})
    if(!user){
        throw new ApiError(404,'User does not exist')
    }

    //password check kar rahe hai ye password req.body se aa raha h
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401,"Invalid user credentials")
    }

    //yaha hame access or generate tokens ko use kar rahe h jo uper likha h
    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    //database ko phir se query bhej rahe hai
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken") 

    // cokkies bhejane se pahale options desigend karne hote hai
    const options = {
        httpOnly: true,  //ye bas server se modify hoga frontend se nahi
        secure: true
    }
    //yaha ham data bhej rahe hain 
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(new ApiResponse(200,{user:loggedInUser,accessToken,refreshToken},'user logged in seccessfully'))
})

// LogOut user
const logoutUser = asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set:{
                refreshToken: undefined 
            }
        },
        {
            new:true
        }
    )
    const options = {
        httpOnly: true,
        secure:true 
    }
    //cookie ko yaha ab clear kar rahe hain
    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User logged Out "))
})

//user token ko refresh kara paye 
const refreshAccessToken = asyncHandler(async(req,res)=>{
    //token ko cokkies se access kar rahe hai
   try {
     const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken
     if(!incomingRefreshToken){
         throw new ApiError(401,"unauthorized request")
     }
 
     // incomingRefreshToken ko verify karenge ab 
     const decodedToken = jwt.verify(incomingRefreshToken,process.env.REFRESH_TOKEN_SECRET)
 
     //mongodb ko query kar rahe hain ab 
     const user = await User.findById(decodedToken?._id)
     if(!user){
         throw new ApiError(401,"Invalid refresh token")
     } 
     if(incomingRefreshToken !== user?.refreshToken){
         throw new ApiError(401,"Refresh token is expired or used")
     }
 
     //ab sari condition sahi h to user ko naya token generate karke dedo
     const options = {
         httpOnly: true,
         secure: true
     }
     const {accessToken,newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
 
     return res
     .status(200)
     .cookie("accessToken",accessToken,options)
     .cookie("refreshToken",newRefreshToken,options)
     .json(
         new ApiResponse(
             200,
             {accessToken,refreshToken:newRefreshToken},"Access token refreshed" 
         )
     )
   } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh token")
   }
}) 



export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
}