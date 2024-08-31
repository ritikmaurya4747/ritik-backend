import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { response } from "express";
import mongoose from "mongoose";


// Access_Token or Refresh_Token -----------------------------
const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    //refreshToken ko database me save kar rahe hai login me use hoga
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    //jab ye sab successful  yaha tak ho jayega to inhe return kar do
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating refresh and access token"
    );
  }
};

// Register user ----------------------------------------------
const registerUser = asyncHandler(async (req, res) => {
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

  const { fullName, email, username, password } = req.body;
  // console.log("email",email);

  if (
    [fullName, email, username, password].some((field) => field?.trim() === "")
  ) {
    throw new ApiError(400, "All fields are required");
  }

  //agar user pahale se hi hain to
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (existedUser) {
    throw new ApiError(409, "User email or username already exists");
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path;
  let coverImageLocalPath;
  if (
    req.files &&
    Array.isArray(req.files.coverImage) &&
    req.files.coverImage.length > 0
  ) {
    coverImageLocalPath = req.files.coverImage[0].path;
  }

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is required");
  }

  //upload on cloudinary files or images
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);

  if (!avatar) {
    throw new ApiError(400, "Avtar file is required");
  }

  //enter in database
  const user = await User.create({
    fullName,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken" //ye sab nahi chahiye
  );
  if (!createdUser) {
    throw new ApiError(500, "Something went worg while registering the user");
  }
  //agar user proper create ho gaya h to use as response bhej do
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User registered successfuly"));
});

// Login user --------------------------------------------------
const loginUser = asyncHandler(async (req, res) => {
  // req body -> data
  // username or email
  // find the user
  // password checks
  // access and refresh token
  // send cokkies
  // video part two time(9:25)

  const { email, username, password } = req.body;
  if (!(username || !email)) {
    //01:05:55
    throw new ApiError(400, "username or email is required");
  }

  // dono me se ek email or username  hona hi chahiye
  const user = await User.findOne({ $or: [{ username }, { email }] });
  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  //password check kar rahe hai ye password req.body se aa raha h
  const isPasswordValid = await user.isPasswordCorrect(password);
  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials");
  }

  //yaha hame access or generate tokens ko use kar rahe h jo uper likha h
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    user._id
  );

  //database ko phir se query bhej rahe hai
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // cokkies bhejane se pahale options desigend karne hote hai
  const options = {
    httpOnly: true, //ye bas server se modify hoga frontend se nahi
    secure: true,
  };
  //yaha ham data bhej rahe hain
  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "user logged in seccessfully"
      )
    );
});

// LogOut user -------------------------------------------------
const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined,
      },
    },
    {
      new: true,
    }
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  //cookie ko yaha ab clear kar rahe hain
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out "));
});

//user token ko refresh kara paye  -----------------------------
const refreshAccessToken = asyncHandler(async (req, res) => {
  //token ko cokkies se access kar rahe hai
  try {
    const incomingRefreshToken =
      req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
      throw new ApiError(401, "unauthorized request");
    }

    // incomingRefreshToken ko verify karenge ab
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    //mongodb ko query kar rahe hain ab
    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }

    //ab sari condition sahi h to user ko naya token generate karke dedo
    const options = {
      httpOnly: true,
      secure: true,
    };
    const { accessToken, newRefreshToken } =
      await generateAccessAndRefreshTokens(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access token refreshed"
        )
      );
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token");
  }
});

// Change Password ----------------------------------------------
const changeCurrentPassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  //user ke andar se user ki id nikal ke password check karenge
  const user = await User.findById(req.user?._id);
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid old password");
  }

  //set new password
  user.password = password;
  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"));
});

// Current User --------------------------------------------------
const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(200, req.user, "Current user fetched successfully");
});

// Update Account Details -----------------------------------------
const updateAccountDetails = asyncHandler(async (req, res) => {
  const { fullName, email } = req.body;
  if (!fullName || !email) {
    throw new ApiError(400, "All fields are required");
  }

  //update karenge
  User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullName,
        email,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"));
});

// Update User Avatar  ---------------------------------------------
const updateUserAvatar = asyncHandler(async (req, res) => {
  //multer file upload kar dega
  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is missing");
  }

  //upload on cloudinary
  const avatar = await uploadOnCloudinary(avatarLocalPath);
  if (!avatar.url) {
    throw new ApiError(400, "Error while uploading on avatar");
  }

  //now update avatar ... yaha ham image ko update kar rahe hain
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        avatar: avatar.url,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Avatar updated successfully"));
});

// Update User coverImage ------------------------------------------
const updateUserCoverImage = asyncHandler(async (req, res) => {
  //multer file upload kar dega
  const coverImageLocalPath = req.file?.path;

  if (!coverImageLocalPath) {
    throw new ApiError(400, "Cover image file is missing");
  }

  //upload on cloudinary
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!coverImage.url) {
    throw new ApiError(400, "Error while uploading on coverImage");
  }

  //now update coverImage ... yaha ham image ko update kar rahe hain
  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        coverImage: coverImage.url, //2:12:00
      },
    },
    { new: true }
  ).select("-password");

  return res
    .status(200)
    .json(new ApiResponse(200, user, "Cover Imgage updated successfully"));
});

// User Channel Profile ---------------------------------------------
const getUserChannelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params;
  if (!username?.trim()) {
    throw new ApiError(400, "username is missing");
  }

  // aggregate method se document find karne ke liye . channel ki value nikal rahe hai(using aggregation and pipelines)
  const channel = await User.aggregate([
    {
      $match: {
        username: username?.toLowerCase(),
      },
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers",
      },
    },
    {
      $lookup: {
        //ye sab hi pipeline hain
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber", //3:04:27
        as: "subscribedTo",
      },
    },
    {
      $addFields: {
        subscribersCount: {
          $size: "$subscribers",
        },
        channelsSubscribedToCount: {
          $size: "subscribedTo",
        },
        isSubscribed: {
          //subcribed kiya h ki nahi
          if: { $in: [req.user?._id, "$subscribers.subscriber"] },
          then: true,
          else: false,
        },
      },
    },
    {
      $project: {
        fullName: 1,
        username: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1,
        avatar: 1,
        coverImage: 1,
        email: 1,
      },
    },
  ]);
  if (!channel?.length) {
    throw new ApiError(404, "channel does not exists");
  }
  return res
    .status(200)
    .json(new ApiResponse(200, channel[0], "user channel fethed successfully"));
});

// User watch history get --------------------------------------------
const getWatchHistory = asyncHandler(async (req, res) => {
  // yaha ham pahale id ko convert kar rahe h
  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Schema.Types.ObjectId(req.user._id)
      }
    },
    {
      $lookup: {
        from: "videos",
        localField: "watchHistory",
        foreignField: "_id",
        as: "watchHistory",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline: [
                {
                  $project: {
                    fullName: 1,
                    username: 1,
                    avatar: 1,
                  },
                },
              ],
            },
          },
          {
            $addFields:{
                owner:{
                    $first: "$owner"
                }
            }
          }
        ],
      },
    },
  ])

  return res
  .status()
  .json(new ApiResponse(200, user[0].watchHistory,"Watch history fetched successfully"))
})

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  updateAccountDetails,
  updateUserAvatar,
  updateUserCoverImage,
  getUserChannelProfile,
//   channel,
  getWatchHistory,
};
