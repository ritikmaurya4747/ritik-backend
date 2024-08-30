import mongoose,{Schema} from "mongoose";

const subscriptionSchema = new Schema({
    subscriber :{
        type: Schema.Types.ObjectId,  //one who is subscribing
        ref: "User"
    },
    channel:{
        //one to whom subscriber is subscribing
        type: Schema.Types.ObjectId,
        ref:"User"
    },
}, {timestamps:true})

export const Subscription = mongoose.model("Subscription", subscriptionSchema)