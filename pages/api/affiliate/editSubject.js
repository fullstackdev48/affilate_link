import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, subjectLines } = req.body.formData;

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.subjectLines = subjectLines;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "Subject line edited successfully" });
  } catch (error) {
    console.error("Error editing subject line:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
