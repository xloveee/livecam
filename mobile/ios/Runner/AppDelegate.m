#import "AppDelegate.h"
#import "GeneratedPluginRegistrant.h"
#import "BroadcastServicePlugin.h"

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  [GeneratedPluginRegistrant registerWithRegistry:self];
  [BroadcastServicePlugin registerWithRegistrar:[self registrarForPlugin:@"BroadcastServicePlugin"]];
  return [super application:application didFinishLaunchingWithOptions:launchOptions];
}

@end
