import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { AuthLayout } from '../components/ui.jsx';

export default function Login() {
  const navigate = useNavigate();
  return (
    <AuthLayout>
      <div className="login-brand">
        <ShieldCheck />
        <div>
          <h1>ARIA</h1>
          <p>Automated Retrieval and Investigation Agent</p>
        </div>
      </div>
      <p>Review host alerts, inspect supporting evidence, and record an analyst decision.</p>
      <button className="sign-in" onClick={() => navigate('/dashboard')}>Open analyst console</button>
    </AuthLayout>
  );
}
