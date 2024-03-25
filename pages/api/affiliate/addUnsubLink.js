import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, unsubLink } = req.body.formData;

  console.log('offLink===>', req.body)

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.unsubLinks += "," + unsubLink;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "Unsub Link added successfully" });
  } catch (error) {
    console.error("Error adding Unsub link:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
