import {asyncHandler} from "../utils/asyncHandler.js";

const registerUser = asyncHandler( async(req,res) =>{
    res.status(500).json({
        message: "edution is the way to save aur nation and people"
    })
})



export {registerUser}