import ConnectDB from "../../../DB/connectDB";
import Offer from "../../../models/Affiliate";

export default async (req, res) => {
  await ConnectDB();

  const { id, subjectLine } = req.body.formData;

  try {
    Offer.findOne({ _id: id }).then((item) => {
      if (item) {
        item.subjectLines += "," + subjectLine;
        item.save();
      }
    })  
    
    res.status(200).json({ success: true, message: "Subject line added successfully" });
  } catch (error) {
    console.error("Error adding subject line:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
};
