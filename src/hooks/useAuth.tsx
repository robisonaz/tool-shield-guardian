import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { getMe, logout as apiLogout, isAuthenticated, getTokens } from "@/lib/api-client";

interface User {
  id: string;
  email: string;
  full_name: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAdmin: boolean;
  signOut: () => Promise<void>;
  setAuthData: (user: User, isAdmin: boolean) => void;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  isAdmin: false,
  signOut: async () => {},
  setAuthData: () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    if (isAuthenticated()) {
      getMe()
        .then((data) => {
          setUser(data.user);
          setIsAdmin(data.isAdmin);
        })
        .catch(() => {
          setUser(null);
          setIsAdmin(false);
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const signOut = async () => {
    await apiLogout();
    setUser(null);
    setIsAdmin(false);
  };

  const setAuthData = (user: User, isAdmin: boolean) => {
    setUser(user);
    setIsAdmin(isAdmin);
  };

  return (
    <AuthContext.Provider value={{ user, loading, isAdmin, signOut, setAuthData }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
