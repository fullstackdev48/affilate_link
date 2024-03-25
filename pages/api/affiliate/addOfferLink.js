import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, offLink } = req.body.formData;

  console.log('offLink===>', req.body)

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.offLinks += "," + offLink;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "Offer Link added successfully" });
  } catch (error) {
    console.error("Error adding Offer link:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
