import { boolean } from "joi";
import mongoose from "mongoose";

const DashboardSchema = new mongoose.Schema({
  offerID: {
    type: String,
    required: true,
  },
  email: {
    type: String,
  },
  timestampe: {
    type: String,
  },
  status: {
    type: boolean
  }
});
const Dashboard = mongoose.models.Dashboard || mongoose.model("Dashboard", DashboardSchema);

export default Dashboard;
