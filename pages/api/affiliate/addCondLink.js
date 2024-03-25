import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, condLink } = req.body.formData;

  console.log('offLink===>', req.body)

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.condLinks += "," + condLink;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "Offer Link added successfully" });
  } catch (error) {
    console.error("Error adding cond link:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
