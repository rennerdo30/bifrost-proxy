import { createBottomTabNavigator } from '@react-navigation/bottom-tabs'
import { View, Text, StyleSheet } from 'react-native'
import { HomeScreen } from '../screens/HomeScreen'
import { ServersScreen } from '../screens/ServersScreen'
import { SettingsScreen } from '../screens/SettingsScreen'
import { StatsScreen } from '../screens/StatsScreen'

const Tab = createBottomTabNavigator()

// Icon component for tabs
function TabIcon({ name, focused }: { name: string; focused: boolean }) {
  const getIcon = () => {
    switch (name) {
      case 'Home':
        return '⚡'
      case 'Servers':
        return '🌐'
      case 'Stats':
        return '📊'
      case 'Settings':
        return '⚙️'
      default:
        return '•'
    }
  }

  return (
    <View style={styles.iconContainer}>
      <Text style={[styles.icon, focused && styles.iconFocused]}>
        {getIcon()}
      </Text>
    </View>
  )
}

export function RootNavigator() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        tabBarIcon: ({ focused }) => <TabIcon name={route.name} focused={focused} />,
        tabBarActiveTintColor: '#3b82f6',
        tabBarInactiveTintColor: '#9ca3af',
        tabBarStyle: {
          backgroundColor: '#111827',
          borderTopColor: '#1f2937',
          paddingTop: 8,
          height: 60,
        },
        tabBarLabelStyle: {
          fontSize: 12,
          fontWeight: '500',
        },
        headerStyle: {
          backgroundColor: '#111827',
          borderBottomColor: '#1f2937',
        },
        headerTintColor: '#f9fafb',
        headerTitleStyle: {
          fontWeight: '600',
        },
      })}
    >
      <Tab.Screen
        name="Home"
        component={HomeScreen}
        options={{ title: 'Bifrost' }}
      />
      <Tab.Screen
        name="Servers"
        component={ServersScreen}
        options={{ title: 'Servers' }}
      />
      <Tab.Screen
        name="Stats"
        component={StatsScreen}
        options={{ title: 'Statistics' }}
      />
      <Tab.Screen
        name="Settings"
        component={SettingsScreen}
        options={{ title: 'Settings' }}
      />
    </Tab.Navigator>
  )
}

const styles = StyleSheet.create({
  iconContainer: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  icon: {
    fontSize: 20,
  },
  iconFocused: {
    transform: [{ scale: 1.1 }],
  },
})
