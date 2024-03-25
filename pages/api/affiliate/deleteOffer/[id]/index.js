import ConnectDB from "../../../../../DB/connectDB";
import Offer from "../../../../../models/Affiliate";

const { parse } = require('url');

export default async (req, res) => {
  await ConnectDB();
  const { id } = req.query;

  try {
    const deletedOffer = await Offer.findByIdAndDelete(id);

    if (!deletedOffer) {
      return res.status(404).json({ message: 'Offer not found' });
    }

    res.json({ success: true, message: 'Offer deleted successfully' });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }

};
