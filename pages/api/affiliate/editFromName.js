import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, fromNames } = req.body.formData;

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.fromNames = fromNames;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "From Name edited successfully" });
  } catch (error) {
    console.error("Error editing from name:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
