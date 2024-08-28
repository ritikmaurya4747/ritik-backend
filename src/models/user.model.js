import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";       // 6:53:34
import bcrypt from "bcrypt";         // 6:44:00

const userSchema = new Schema(
    {
        username:{
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim:true, 
            index: true    //database searching me asani ho
        },
        email:{
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim:true, 
        },
        fullName:{
            type: String,
            required: true,
            trim:true, 
            index: true
        },
        avatar:{
            type: String,   //Cloudinary url
            required: true,
        },
        coverImage:{
            type: String
        },
        watchHistory:{
            type: Schema.Types.ObjectId,
            ref: "Video"
        },
        password:{
            type: String,
            required:[true,"Password is required"]
        },
        refreshToken:{
            type: String
        }, 
    }, 
    {
        timestamps:true    //date batata hain
    }
)

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next();
    this.password = bcrypt.hash(this.password, 10)
    next()
})

//this is to check password is correct or not 
userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

//access to generate Accesstoken 
userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn:process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}

// access to generate Refreshtoken 
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn:process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}

export const User = mongoose.model('User',userSchema) 