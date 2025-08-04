import math
from typing import Dict, List, Optional, Tuple

# Singapore Polytechnics Collection Points
COLLECTION_POINT_DATA = [
    {
        'name': 'Singapore Polytechnic',
        'address': '500 Dover Rd, Singapore 139651',
        'coordinates': {'lat': 1.3099, 'lng': 103.7762}
    },
    {
        'name': 'Ngee Ann Polytechnic',
        'address': '535 Clementi Road, Singapore 599489',
        'coordinates': {'lat': 1.3319, 'lng': 103.7749}
    },
    {
        'name': 'Temasek Polytechnic',
        'address': '21 Tampines Ave 1, Singapore 529757',
        'coordinates': {'lat': 1.3450, 'lng': 103.9330}
    },
    {
        'name': 'Nanyang Polytechnic',
        'address': '180 Ang Mo Kio Ave 8, Singapore 569830',
        'coordinates': {'lat': 1.3777, 'lng': 103.8492}
    },
    {
        'name': 'Republic Polytechnic',
        'address': '9 Woodlands Ave 9, Singapore 738964',
        'coordinates': {'lat': 1.4436, 'lng': 103.7865}
    }
]

def calculate_distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """
    Calculate the great circle distance between two points on the earth (specified in decimal degrees)
    Returns distance in kilometers
    """
    # Convert decimal degrees to radians
    lat1, lng1, lat2, lng2 = map(math.radians, [lat1, lng1, lat2, lng2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlng = lng2 - lng1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlng/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Radius of earth in kilometers
    r = 6371
    
    return c * r

def find_nearest_collection_point(latitude: float, longitude: float) -> Optional[Dict]:
    """
    Find the nearest collection point to the given coordinates
    
    Args:
        latitude: User's latitude
        longitude: User's longitude
    
    Returns:
        Dict containing collection point information with distance, or None if no collection points available
    """
    if not COLLECTION_POINT_DATA:
        return None
    
    nearest_collection_point = None
    min_distance = float('inf')
    
    for collection_point in COLLECTION_POINT_DATA:
        point_lat = collection_point['coordinates']['lat']
        point_lng = collection_point['coordinates']['lng']
        
        distance = calculate_distance(latitude, longitude, point_lat, point_lng)
        
        if distance < min_distance:
            min_distance = distance
            nearest_collection_point = collection_point.copy()
    
    if nearest_collection_point:
        nearest_collection_point['distance'] = round(min_distance, 2)
    
    return nearest_collection_point

def get_all_collection_points() -> List[Dict]:
    """Get all available collection points"""
    return COLLECTION_POINT_DATA.copy()

def add_collection_point(name: str, address: str, latitude: float, longitude: float) -> bool:
    """
    Add a new collection point to the data
    
    Args:
        name: Collection point name
        address: Collection point address  
        latitude: Collection point latitude
        longitude: Collection point longitude
    
    Returns:
        True if added successfully
    """
    try:
        collection_point = {
            'name': name,
            'address': address,
            'coordinates': {'lat': latitude, 'lng': longitude}
        }
        COLLECTION_POINT_DATA.append(collection_point)
        return True
    except Exception:
        return False

# Legacy function name for backwards compatibility
def find_nearest_carpark(latitude: float, longitude: float) -> Optional[Dict]:
    """Legacy function name - redirects to find_nearest_collection_point"""
    return find_nearest_collection_point(latitude, longitude)