import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, fromName } = req.body.formData;

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.fromNames += "," + fromName;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "Offer Link added name" });
  } catch (error) {
    console.error("Error adding name:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
